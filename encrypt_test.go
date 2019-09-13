package fpast2l

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func Test_encrypt(t *testing.T) {
	t.Parallel()

	ci, err := chacha20poly1305.NewX(randomBytes(make([]byte, KeySize)))
	if nil != err {
		t.Fatal(err)
	}

	pa := pae{} // pae without a footer
	x := randomBytes(make([]byte, nonceSize))
	f := randomString(32)
	pa.init(0)
	pa.setNonce(x)

	pb := pae{} // pae with a footer but same nonce as pa
	pb.init(len(f))
	pb.setNonce(x)
	pb.setFooter(f)

	for i, b := range [...][]byte{
		nil, {}, {0},
		randomBytes(make([]byte, 64)),
		randomBytes(make([]byte, 1<<10)),
	} {
		for j, p := range [...]pae{pa, pb} {
			b0 := make([]byte, len(b), len(b)+tagSize)
			copy(b0, b)

			b1 := encrypt(ci, b0, p)

			if &b0[:1][0] != &b1[:1][0] {
				t.Errorf("i=%d: b0 was relocated", i*10+j)
			}

			b := ci.Seal(nil, p.getNonce(), b, p.asBytes())
			if !bytes.Equal(b, b1) {
				exp := hex.EncodeToString(b)
				act := hex.EncodeToString(b1)
				t.Fatalf("i=%d: expected b1 = Hex(%q), actual b1 = Hex(%q)",
					i*10+j, exp, act)
			}
		}
	}
}

func Test_encode(t *testing.T) {
	t.Parallel()

	pa := pae{} // pae without a footer
	x := randomBytes(make([]byte, nonceSize))
	f := randomString(32)
	pa.init(0)
	pa.setNonce(x)

	pb := pae{} // pae with a footer but same nonce as pa
	pb.init(len(f))
	pb.setFooter(f)
	copy(pb, pa)

	for i, b := range [...][]byte{
		randomBytes(make([]byte, tagSize)),
		randomBytes(make([]byte, tagSize+64)),
		randomBytes(make([]byte, tagSize+(1<<10))),
	} {
		for j, p := range [...]pae{pa, pb} {
			s := encode(b, p)
			q := header + b64.EncodeToString(p.getNonce()) + b64.EncodeToString(b)
			if f := p.getFooter(); 0 != len(f) {
				q += "." + b64.EncodeToString(f)
			}

			if s != q {
				t.Errorf("i=%d: expected s = %q, actual %q", i*10+j, q, s)
			}
		}
	}
}
