package fpast2l

import (
	"crypto/rand"

	"golang.org/x/crypto/blake2b"
)

// generateNonce generates encryption nonce
// as described in the PASETO v2 specicification.
//
// It computes the BLAKE2b MAC of m
// using a crypto-safe pseudorandom key
// appending the result to p
// and returning it as b.
func generateNonce(p, m []byte) (b []byte) {
	p, b = extend(p, nonceSize)
	b = b[len(p):][:nonceSize]

	if _, err := rand.Read(b); nil != err {
		panic(AsError(err))
	}

	h, err := blake2b.New(nonceSize, b)
	if nil != err {
		panic(AsError(err))
	}

	if _, err = h.Write(m); nil != err {
		panic(AsError(err))
	}

	return h.Sum(p)
}
