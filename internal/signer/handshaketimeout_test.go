// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/rpc"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the frontend's bound on the signer handshake", func() {
	var (
		psk                    []byte
		serverConn, clientConn net.Conn
	)

	BeforeEach(func() {
		psk = make([]byte, pskLen)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred())

		serverConn, clientConn = net.Pipe()
		DeferCleanup(serverConn.Close)
		DeferCleanup(clientConn.Close)
	})

	// handshakeAsync runs the frontend's side in a goroutine, so a regression
	// that removes the bound fails the spec at Eventually's limit instead of
	// hanging the suite until Ginkgo's own timeout.
	handshakeAsync := func(ctx context.Context, timeout time.Duration) <-chan error {
		done := make(chan error, 1)
		go func() { done <- clientHandshakeWithin(ctx, clientConn, psk, timeout) }()
		return done
	}

	It("gives up on a signer that never sends its nonce, and names the signer", func() {
		// The signer writes its nonce only once its whole Init has returned, so
		// this is a signer wedged in Init: alive, holding its end of the
		// socketpair, saying nothing. serverConn is never touched.
		done := handshakeAsync(context.Background(), 100*time.Millisecond)

		var err error
		Eventually(done, 5*time.Second).Should(Receive(&err),
			"the frontend must not wait for ever on a signer that never answers")
		Expect(err).To(MatchError(ErrHandshakeTimeout))
		Expect(err).To(MatchError(ContainSubstring("role signer")),
			"the error must point at the signer's own log, which names the step it is stuck in")
	})

	It("gives up on a signer that stops after sending its nonce", func() {
		// The bound covers the whole exchange, not only the first read. The
		// signer reports the flight it took over a channel rather than with an
		// Expect, which could run after the spec has ended; and the spec checks
		// that flight arrived, or a late goroutine would leave it passing on
		// the first read, which the spec above already covers.
		tookFlight := make(chan error, 1)
		go func() {
			nonce := make([]byte, nonceLen)
			_, _ = rand.Read(nonce)
			if _, err := serverConn.Write(nonce); err != nil {
				tookFlight <- err
				return
			}
			// Take the frontend's flight so its write does not block on the
			// synchronous pipe, then never send the counter-proof.
			_, err := io.ReadFull(serverConn, make([]byte, nonceLen+sha256.Size))
			tookFlight <- err
		}()

		done := handshakeAsync(context.Background(), time.Second)

		Eventually(tookFlight, 5*time.Second).Should(Receive(BeNil()),
			"the signer must have sent its nonce and taken the frontend's flight")
		var err error
		Eventually(done, 5*time.Second).Should(Receive(&err))
		Expect(err).To(MatchError(ErrHandshakeTimeout))
	})

	// A signer that exits closes its end of the socketpair, and one holding the
	// wrong PSK fails the proof. Both are answers, not silence: reported as a
	// timeout they would tell an operator that a crashed or impostor signer was
	// still initialising, and the frontend would log that it gave up waiting.
	It("reports a signer that exits as a failed handshake, at once, not as a timeout", func() {
		// Closed while the frontend is waiting, as a signer that dies in Init
		// does it.
		done := handshakeAsync(context.Background(), time.Minute)
		Consistently(done, 100*time.Millisecond).ShouldNot(Receive())
		Expect(serverConn.Close()).To(Succeed())

		var err error
		Eventually(done, 5*time.Second).Should(Receive(&err),
			"a closed socketpair must end the wait at once, not at its minute")
		Expect(err).To(MatchError(ContainSubstring("PSK handshake failed")))
		Expect(errors.Is(err, ErrHandshakeTimeout)).To(BeFalse())
	})

	It("reports a signer with the wrong PSK as a failed handshake, not as a timeout", func() {
		otherPSK := make([]byte, pskLen)
		_, err := rand.Read(otherPSK)
		Expect(err).NotTo(HaveOccurred())
		go func() {
			// Closed on failure, as the real signer's Serve does by returning,
			// so the frontend's read of the counter-proof ends.
			if serverHandshake(serverConn, otherPSK) != nil {
				_ = serverConn.Close()
			}
		}()
		done := handshakeAsync(context.Background(), time.Minute)

		Eventually(done, 5*time.Second).Should(Receive(&err))
		Expect(err).To(MatchError(ContainSubstring("PSK handshake failed")))
		Expect(errors.Is(err, ErrHandshakeTimeout)).To(BeFalse())
	})

	It("stops waiting when its context is cancelled, and does not call that a timeout", func() {
		// A SIGTERM during a long start. Reported as a deadline it would tell an
		// operator who stopped the service that the signer had wedged.
		ctx, cancel := context.WithCancel(context.Background())
		done := handshakeAsync(ctx, time.Minute)

		Consistently(done, 100*time.Millisecond).ShouldNot(Receive(),
			"nothing has failed yet, so the wait must still be running")
		cancel()

		var err error
		Eventually(done, 5*time.Second).Should(Receive(&err),
			"cancelling the context must end the wait well before its minute")
		Expect(err).To(MatchError(context.Canceled))
		Expect(errors.Is(err, ErrHandshakeTimeout)).To(BeFalse())
	})

	It("lifts the deadline once the handshake succeeds, so later calls are not bound by it", func() {
		// The conn goes on to carry every Sign RPC for the life of the process.
		// A deadline left armed would fail the first one made after it.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())

		go func() {
			if err := serverHandshake(serverConn, psk); err != nil {
				_ = serverConn.Close()
				return
			}
			srv := rpc.NewServer()
			_ = srv.RegisterName("Signer", &Service{key: key})
			srv.ServeConn(serverConn)
		}()

		const bound = 200 * time.Millisecond
		Expect(clientHandshakeWithin(context.Background(), clientConn, psk, bound)).To(Succeed())

		// Past the bound before the first call, which is what a deadline left
		// armed would fail.
		time.Sleep(2 * bound)

		rs := NewRemoteSigner(clientConn, key.Public())
		digest := sha256.Sum256([]byte("after the handshake deadline"))
		sig, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
		Expect(err).NotTo(HaveOccurred(), "a call after the handshake's bound has passed")
		Expect(ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig)).To(BeTrue())
	})

	// Checked before any descriptor is touched, so it is reachable here. A
	// negative bound would otherwise arm a deadline already past, and report a
	// healthy signer as one that never finished initialising.
	DescribeTable("refuses a bound that would not bind",
		func(timeout time.Duration) {
			_, err := DialConn(context.Background(), timeout)
			Expect(err).To(MatchError(ContainSubstring("must be positive")))
		},
		Entry("zero", time.Duration(0)),
		Entry("negative", -time.Second),
	)
})
