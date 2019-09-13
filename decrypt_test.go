package fpast2l

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func Test_decrypt(t *testing.T) {
	t.Parallel()

	k := randomBytes(make([]byte, KeySize))
	ci, err := chacha20poly1305.NewX(k)
	if nil != err {
		t.Fatal(err)
	}

	pa := pae{}
	x := randomBytes(make([]byte, nonceSize))
	f := randomString(32)
	pa.init(0)
	pa.setNonce(x)

	pb := pae{}
	pb.init(len(f))
	pb.setNonce(x)
	pb.setFooter(f)

	encrypt := func(b []byte, a pae) []byte {
		return ci.Seal(nil, a.getNonce(), b, a.asBytes())
	}

	badEncryption := func(t *testing.T) {
		t.Parallel()
		for i, b := range [...][]byte{
			nil, {}, {0}, // insufficient length, not enough bytes for tag
			randomBytes(make([]byte, tagSize)),
			randomBytes(make([]byte, 64)),
			randomBytes(make([]byte, 1<<10)),
			// good encryption, but missing poly1305 auth tag
			encrypt(randomBytes(make([]byte, 1<<10)), pb)[:(1 << 10)],
		} {
			_, err := decrypt(ci, b, pa)
			if nil == err {
				t.Errorf("i=%d: expected error", i)
			}

			if err != ErrBadEncryption {
				t.Errorf("i=%d: expected ErrBadEncryption, actual error(%q)",
					i, err.Error())
			}
		}
	}

	t.Run("badEncryption", badEncryption)

	for i, b := range [...][]byte{
		nil, {}, {0},
		randomBytes(make([]byte, 64)),
		randomBytes(make([]byte, 1<<10)),
	} {
		for j, p := range [...]pae{pa, pb} {
			b0 := encrypt(b, p)
			b1, err := decrypt(ci, b0, p)
			if nil != err {
				t.Errorf("i=%d: %v", i*10+j, err)
			}

			if &b1[:1][0] != &b0[:1][0] {
				t.Errorf("i=%d: b0 was relocated", i*10+j)
			}

			if !bytes.Equal(b, b1) {
				exp := hex.EncodeToString(b)
				act := hex.EncodeToString(b1)
				t.Fatalf("i=%d: expected b1 = Hex(%q), actual b1 = Hex(%q)",
					i*10+j, exp, act)
			}
		}
	}
}

func Test_decode(t *testing.T) {
	t.Parallel()

	badHeader := func(t *testing.T) {
		t.Parallel()

		for i, s := range [...]string{
			"", "\x00",
			b64.EncodeToString(randomBytes(make([]byte, 16))),
			"v2",
			"v2.local",
			"v2-local-",
			"v2/local." + b64.EncodeToString(randomBytes(make([]byte, 16))),
		} {
			_, _, err := decode(nil, s)

			if nil == err {
				t.Fatalf("i = %d, expected error", i)
			}

			if err != ErrBadHeader {
				t.Fatalf("i = %d, expected ErrBadHeader, actual error(%q)",
					i, err.Error())
			}
		}
	}

	badEncoding := func(t *testing.T) {
		t.Parallel()

		for i, s := range []string{
			header,
			header + ".",
			header + "..",
			header + "/+",

			// insufficient length
			header + b64.EncodeToString(randomBytes(make([]byte,
				nonceSize+tagSize-1))),

			// illegal chars in payload
			header + b64.EncodeToString(randomBytes(make([]byte,
				nonceSize+tagSize-1))) + "/+",

			// trailing separator ('.')
			header + b64.EncodeToString(randomBytes(make([]byte,
				nonceSize+tagSize-1))) + ".",

			// illegal chars in footer
			header + b64.EncodeToString(randomBytes(make([]byte,
				nonceSize+tagSize-1))) + "./+",
		} {
			_, _, err := decode(nil, s)

			if nil == err {
				t.Fatalf("i = %d, expected error", i)
			}

			if err != ErrBadEncoding {
				t.Fatalf("i = %d, expected ErrBadEncoding, actual error(%q)",
					i, err.Error())
			}
		}
	}

	for name, fn := range map[string]func(*testing.T){
		"badHeader":   badHeader,
		"badEncoding": badEncoding,
	} {
		t.Run(name, fn)
	}

	key := make([]byte, KeySize)
	if _, err := rand.Read(key); nil != err {
		t.Fatal(err)
	}

	for i, s := range []string{
		// valid token with a random (valid minimum) length payload
		header +
			b64.EncodeToString(
				randomBytes(make([]byte, nonceSize+tagSize+rand.Intn(32))),
			),

		// valid token with a random (valid minimum) length payload
		// and a random (minimum 1byte) length footer
		header +
			b64.EncodeToString(
				randomBytes(make([]byte, nonceSize+tagSize+rand.Intn(32))),
			) + "." +
			b64.EncodeToString(
				randomBytes(make([]byte, 1+rand.Intn(15))),
			),

		// tokens generated with random data from reference implementation
		rPASTEncrypt(key, []byte{}, ""),
		rPASTEncrypt(key, randomBytes(make([]byte, 16+rand.Intn(16))), ""),
		rPASTEncrypt(key, randomBytes(make([]byte, 16+rand.Intn(16))),
			randomString(1+rand.Intn(15))),
	} {
		ss := strings.SplitN(s[len(header):], ".", 2)
		x, _ := b64.DecodeString(ss[0][:b64NonceSize])
		b, _ := b64.DecodeString(ss[0][b64NonceSize:])
		f := []byte(nil)
		if len(ss) == 2 {
			f, _ = b64.DecodeString(ss[1])
		}

		c, a, err := decode(nil, s)
		if nil != err {
			t.Logf("%q", s)
			t.Fatalf("i=%d: %v", i, err)
		}

		if !bytes.Equal(b, c) {
			exp := hex.EncodeToString(b)
			act := hex.EncodeToString(c)
			t.Errorf("i=%d: expected Hex(%q), actual Hex(%q)", i, exp, act)
		}

		if _x := a.getNonce(); !bytes.Equal(_x, x) {
			exp := hex.EncodeToString(x)
			act := hex.EncodeToString(_x)
			t.Errorf("i=%d: expected Hex(%q), actual Hex(%q)", i, exp, act)
		}

		if _f := a.getFooter(); !bytes.Equal(_f, f) {
			exp := hex.EncodeToString(f)
			act := hex.EncodeToString(_f)
			t.Errorf("i=%d: expected Hex(%q), actual Hex(%q)", i, exp, act)
		}
	}
}
