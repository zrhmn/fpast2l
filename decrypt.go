package fpast2l

import (
	"crypto/cipher"
	"strings"
	"unsafe"
)

// decrypt deciphers the ciphertext b
// using a as additional associated data
// and returns the plaintext as r
// or an error if decryption failed.
//
// Decryption is performed in-place
// meaning contents of b are overwritten
// and r is backed by the same memory as b.
func decrypt(ci cipher.AEAD, b []byte, a pae) (r []byte, err error) {
	if nil == ci {
		panic(errBadCipher)
	}

	a.checkLength()
	b, err = ci.Open(b[:0], a.getNonce(), b, a.asBytes())
	if err != nil {
		return nil, ErrBadEncryption
	}

	return b, nil
}

// decode parses s as a PASETO v2 local token,
// appends the encrypted payload to p and returns it as b
// along with assembled pre-authentication encoding a,
// or an error if s cannot be parsed.
func decode(p []byte, s string) (b []byte, a pae, err error) {
	n := len(s)
	if n < headerSize || s[:headerSize] != header {
		return nil, nil, ErrBadHeader
	}

	s, n = s[headerSize:], n-headerSize
	if n < b64NonceSize {
		return nil, nil, ErrBadEncoding
	}

	x, f := s[:b64NonceSize], ""
	s, n = s[b64NonceSize:], n-b64NonceSize

	if 0 == n {
		return nil, nil, ErrBadEncoding
	}

	switch i := strings.IndexByte(s, '.'); i {
	case 0, n - 1:
		return nil, nil, ErrBadEncoding
	case -1:
		break // no footer, noop
	default:
		f = s[i+1:]
		s, n = s[:i], i
	}

	if n < b64TagSize {
		return nil, nil, ErrBadEncoding
	}

	k := b64.DecodedLen(n)
	m := b64.DecodedLen(len(f))

	p, b = extend(p, k+minPAESize+m)
	b = b[len(p):][:k]
	a = pae(b[k:k])

	a.init(m)

	if _, err := a.setNonceB64(x); nil != err {
		return nil, nil, ErrBadEncoding
	}

	if _, err := a.setFooterB64(f); nil != err {
		return nil, nil, ErrBadEncoding
	}

	if _, err := b64.Decode(b, *(*[]byte)(unsafe.Pointer(&s))); nil != err {
		return nil, nil, ErrBadEncoding
	}

	return
}
