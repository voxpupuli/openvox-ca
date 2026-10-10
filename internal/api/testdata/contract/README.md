# Puppet CA API contract

Recorded from OpenVox Server by `go run ./test/contract/record`; see
docs/development/testing.md#the-puppet-ca-api-contract. Do not edit anything
here by hand: re-record instead.

`cadir/ca_key.pem` and the CA it signs for are throwaways, generated
inside a disposable container for this recording and committed so the specs can
use them. Nothing should trust them.
