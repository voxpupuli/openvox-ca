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

// The failure this pins is a signer that is *wedged*, not one that is dead.
// A dead signer breaks the connection and net/rpc fails every pending call on
// its own, so a spec that closed the socket would pass with the deadline
// removed. A child that accepted the call and will never answer is the case
// only the deadline covers, and it is the one an operator meets: the frontend
// waits for a reply that is not coming, with no per-call bound, while callers
// pile up behind it.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"net/rpc"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// wedgedSigner accepts a Sign call and never returns from it.
type wedgedSigner struct {
	entered chan struct{}
	release chan struct{}
}

func (w *wedgedSigner) Sign(_ *SignRequest, _ *SignResponse) error {
	close(w.entered)
	<-w.release
	return nil
}

var _ = Describe("RemoteSigner per-call deadline", func() {
	var (
		rs      *RemoteSigner
		wedged  *wedgedSigner
		digest  [32]byte
		testKey *ecdsa.PrivateKey
	)

	BeforeEach(func() {
		var err error
		testKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())

		wedged = &wedgedSigner{
			entered: make(chan struct{}),
			release: make(chan struct{}),
		}

		serverConn, clientConn := net.Pipe()
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", wedged)).To(Succeed())
		go server.ServeConn(serverConn)

		rs = &RemoteSigner{
			client:  rpc.NewClient(clientConn),
			pub:     testKey.Public(),
			timeout: 50 * time.Millisecond,
		}
		DeferCleanup(func() {
			// Let the handler return before tearing the connection down, so
			// the suite does not leave a goroutine parked on release.
			close(wedged.release)
			rs.Close()
		})

		digest = sha256.Sum256([]byte("test data"))
	})

	It("gives up on a signer that accepts the call and never answers", func() {
		done := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			_, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
			done <- err
		}()

		// The call really did reach the signer: this is a wedged child, not a
		// connection that never carried the request.
		Eventually(wedged.entered).Should(BeClosed())

		var err error
		Eventually(done, time.Second).Should(Receive(&err))
		Expect(err).To(MatchError(ErrSignTimeout))
	})

	It("defaults to the two-minute backstop when no timeout is set", func() {
		// Guards the zero value: RemoteSigner is constructed directly in
		// places, and a zero field must not mean "expire immediately".
		Expect((&RemoteSigner{}).signTimeout()).To(Equal(defaultRemoteSignTimeout))
		Expect(rs.signTimeout()).To(Equal(50 * time.Millisecond))
	})

	// The deadline must not cost throughput on a signer that is merely busy:
	// a healthy reply arriving before the timer still has to be returned.
	It("returns a normal signature unaffected", func() {
		serverConn, clientConn := net.Pipe()
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", &Service{key: testKey})).To(Succeed())
		go server.ServeConn(serverConn)

		healthy := &RemoteSigner{client: rpc.NewClient(clientConn), pub: testKey.Public()}
		DeferCleanup(healthy.Close)

		sig, err := healthy.Sign(rand.Reader, digest[:], crypto.SHA256)
		Expect(err).NotTo(HaveOccurred())
		Expect(ecdsa.VerifyASN1(&testKey.PublicKey, digest[:], sig)).To(BeTrue())
		Expect(errors.Is(err, ErrSignTimeout)).To(BeFalse())
	})
})
