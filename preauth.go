package fpast2l

import "unsafe"

const minPAESize = 8 + 8 + headerSize + 8 + nonceSize + 8

var (
	errBadExtraCap    = internal("negative extra-capacity")
	errBadNonceLength = internal("bad nonce length")
	errBadPAELength   = internal("bad pae length")

	zeroNonce [nonceSize]byte
)

// pae is a byte slice containing the pre-authentication encoding
// as described in the PASETO v2 specification.
//
// Methods of pae are used to assemble
// the pre-authentication encoding
// with as few allocations as possible.
type pae []byte

// init initializes pae to a non-nil byte slice.
// Length of backing slice is always set to minPAELength.
// xcap can be used to order extra capacity
// (e.g. to pre-allocate for footer).
//
// init also fills in the known PAE components:
// headerSize, header and nonceSize
// and zeroes out the space for nonce and footerSize.
func (p *pae) init(xcap int) {
	if xcap < 0 {
		panic(errBadExtraCap)
	}

	b := p.asBytes()
	_, b = extend(b[:0], minPAESize+xcap)
	b = b[:minPAESize]

	i := 0
	i += putUint64LE(b[i:][:8], 3)
	i += putUint64LE(b[i:][:8], headerSize)
	i += copy(b[i:][:headerSize], header)
	i += putUint64LE(b[i:][:8], nonceSize)
	i += copy(b[i:][:nonceSize], zeroNonce[:])
	i += putUint64LE(b[i:][:8], 0)

	*p = pae(b)
}

// getNonce returns the nonce within pae.
func (p *pae) getNonce() []byte {
	p.checkLength()

	b := p.asBytes()
	return b[minPAESize-8-nonceSize:][:nonceSize]
}

// generateNonce fills in the nonce
// from the plaintext m. (Also see generateNonce.)
func (p *pae) generateNonce(m []byte) []byte {
	p.checkLength()
	x := p.getNonce()

	return generateNonce(x[:0], m)
}

// setNonce writes the nonce x as-is
// to the location within pae.
func (p *pae) setNonce(x []byte) []byte {
	p.checkLength()
	if nonceSize != len(x) {
		panic(errBadNonceLength)
	}

	r := p.getNonce()
	copy(r, x)
	return r
}

// setNonceB64 decodes X
// as RFC 4648 sec. 5 Base64 encoding without padding
// and writes the result to the location with pae.
//
// An error is returned if X is invalid.
func (p *pae) setNonceB64(X string) ([]byte, error) {
	p.checkLength()
	if b64NonceSize != len(X) {
		panic(errBadNonceLength)
	}

	x := p.getNonce()
	_, err := b64.Decode(x, *(*[]byte)(unsafe.Pointer(&X)))
	return x, err
}

// getFooter returns the footer within pae.
func (p *pae) getFooter() []byte {
	p.checkLength()

	b := p.asBytes()[minPAESize:]
	if 0 == len(b) {
		return nil
	}

	return b
}

// setFooter sets the footer length with pae
// and appends f to pae.
//
// p is overwritten if relocation occurs as result of append.
func (p *pae) setFooter(f string) []byte {
	p.checkLength()
	b := p.asBytes()

	k := len(f)
	if 0 == k {
		b = b[:minPAESize]
	} else {
		_, b = extend(b[:minPAESize], k)
		copy(b[minPAESize:], f)
	}

	putUint64LE(b[minPAESize-8:][:8], k)
	*p = pae(b)
	return p.getFooter()
}

// setFooterB64 decodes F
// as RFC 4648 sec. 5 Base64 encoding without padding
// and appends the result to pae
// also setting footer length within pae.
//
// The footer component of pae is set to empty
// and an error is returned
// if F is invalid.
//
// p is overwritten if relocation occurs as result of append.
func (p *pae) setFooterB64(F string) ([]byte, error) {
	p.checkLength()
	b := p.asBytes()

	k := b64.DecodedLen(len(F))
	if 0 == k {
		b = b[:minPAESize]
	} else {
		_, b = extend(b[:minPAESize], k)
		if _, err := b64.Decode(b[minPAESize:],
			*(*[]byte)(unsafe.Pointer(&F))); nil != err {
			return p.setFooter(""), ErrBadEncoding
		}
	}

	putUint64LE(b[minPAESize-8:][:8], k)
	*p = pae(b)
	return p.getFooter(), nil
}

// checkLength panics
// if the length of the byte slice backing pae
// is less than minPAESize.
//
// It acts as a circuit-breaker in the other pae methods
// causing a trip if things are out of place.
func (p *pae) checkLength() {
	if len(*p) < minPAESize {
		panic(errBadPAELength)
	}
}

// asBytes returns the backing byte slice of pae.
func (p *pae) asBytes() []byte {
	return []byte(*p)
}

// putUint64LE writes 64-bit LittleEndian representation of i to p,
// returning the number of bytes written (always 8).
//
// If len(p) < 8, putUint64LE panics.

// putUint64LE writes
// the 64-bit little-endian representation
// of i to p.
//
// putUint64LE panics of len(p) < 8.
func putUint64LE(p []byte, i int) int { le.PutUint64(p, uint64(i)); return 8 }

// extend ensure b is allocated to a capacity of at least n + c
// where n = len(b). It reallocates b only if necessary, i.e.
// b does not already have capacity equal to at least n + c.
//
// extend returns 2 slices backed by the same storage array,
// where b0 is a copy of b, i.e. len(b0) == len(b)
// and b1 is an extension of b up to n + c, i.e.
// len(b1) == len(b) + c
func extend(b []byte, c int) (b0 []byte, b1 []byte) {
	var n, k = len(b), cap(b)
	if k-n >= c {
		return b, b[:n+c]
	}

	b0 = make([]byte, n, n+c)
	copy(b0, b)
	return b0, b0[:n+c]
}
