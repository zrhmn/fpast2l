package fpast2l

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"unsafe"

	"github.com/aead/poly1305"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	nonceSize = chacha20poly1305.NonceSizeX
	tagSize   = poly1305.TagSize

	header     = "v2.local."
	headerSize = len(header)
)

var (
	le  = binary.LittleEndian
	b64 = base64.RawURLEncoding

	b64NonceSize = b64.EncodedLen(nonceSize)
	b64TagSize   = b64.EncodedLen(tagSize)

	errBadTagSize = internal("bad tag size")
	errBadCipher  = internal("bad/nil cipher.AEAD")
)

// encrypt encrypts the plaintext in b
// using a as additional associated data
// and returns the ciphertext r.
//
// Encryption is performed in-place
// meaning contents of b are overwritten
// and r is backed by the same memory as b if
// b has sufficient capacity to hold the authentication tag.
func encrypt(ci cipher.AEAD, b []byte, a pae) (r []byte) {
	if nil == ci {
		panic(errBadCipher)
	}

	a.checkLength()
	return ci.Seal(b[:0], a.getNonce(), b, a.asBytes())
}

// encode converts the ciphertext in b
// and the nonce and footer from pre-authentication encoding a
// into a PASETO v2 local token.
func encode(b []byte, a pae) string {
	a.checkLength()
	if len(b) < tagSize {
		panic(errBadTagSize)
	}

	f := a.getFooter()

	k := b64.EncodedLen(len(b))
	n := headerSize + b64NonceSize + k
	if 0 != len(f) {
		n += 1 + b64.EncodedLen(len(f))
	}

	sb := make([]byte, n)
	n = copy(sb, header)
	b64.Encode(sb[n:], a.getNonce())
	n += b64NonceSize
	b64.Encode(sb[n:], b)
	n += k

	if 0 != len(f) {
		sb[n] = '.'
		n++

		b64.Encode(sb[n:], f)
	}

	return *(*string)(unsafe.Pointer(&sb))
}
