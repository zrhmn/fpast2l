package fpast2l

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the required length of the encryption key.
const KeySize = chacha20poly1305.KeySize

// Engine is a PASETO generator.
// It can be reused concurrently
// to generate multiple v2 local tokens
// as long as the encryption key and footer stay the same.
//
// To facilitate concurrency, Engine should not mutate.
// Make copies (e.g. WithFooter), avoid references.
type Engine struct {
	ci cipher.AEAD
	f  string
}

// New constructs and returns a new Engine,
// with the encryption key K.
// New will panic if len(K) is not exactly KeySize bytes.
func New(K []byte) (eng Engine) {
	if len(K) != KeySize {
		panic(ErrBadKeySize)
	}

	err := error(nil)
	if eng.ci, err = chacha20poly1305.NewX(K); nil != err {
		panic(err)
	}

	return
}

// WithFooter returns a copy of Engine
// with the footer in the copy set to f.
func (eng Engine) WithFooter(f string) Engine { eng.f = f; return eng }

// Encrypt creates and returns a new PASETO v2 local token
// from the payload contained in b.
// b is encrypted in-place,
// meaning the contents of b will be overwritten with raw ciphertext.
// It is safe to reuse b or throw it away.
func (eng Engine) Encrypt(b []byte) string {
	if nil == eng.ci {
		panic(ErrEngNotInitialized)
	}

	_, p := extend(b, tagSize+minPAESize+len(eng.f))
	p = p[len(b):]

	a := pae(p)
	a.init(len(eng.f))
	a.generateNonce(b)
	a.setFooter(eng.f)

	return encode(encrypt(eng.ci, b, a), a)
}

// Decrypt parses and decrypt s as a PASETO v2 local token.
// If successful, resulting plaintext is appended to p and returned.
//
// Extra capacity of p,
// if available, is used for computation.
// Even if the encryption is unsuccessful, p should be
// overwritten or thrown away.
func (eng Engine) Decrypt(p []byte, s string) (b []byte, err error) {
	b, a, err := decode(p, s)
	if nil != err {
		return nil, err
	}

	b, err = decrypt(eng.ci, b, a)
	if nil != err {
		return nil, err
	}

	return
}

// Encrypt is a shorthand for creating a new Engine with the given K
// and f, encrypting b and returning the formatted local v2 PASETO.
// It is recommended to use Engine.Encrypt if this operation is going
// to be performed more than once with the same K.

// Encrypt is a shorthand for
// creating a new Engine with K as encryption key and f as footer,
// encrypting and encoding b
// and returning the PASETO v2 local token.
//
// It is recommended to use Engine
// unless this is a one-time operation.
func Encrypt(K, b []byte, f string) string {
	return New(K).WithFooter(f).Encrypt(b)
}

// Decrypt is a shorthand for
// creating a new Engine with K as decryption key and f as footer,
// decoding and decrypting s as a PASETO v2 local token
// appending the resulting payload to p
// and returning it.
//
// It is recommended to use Engine
// unless this is a one-time operation.
func Decrypt(K, p []byte, s string) ([]byte, error) {
	return New(K).Decrypt(p, s)
}
