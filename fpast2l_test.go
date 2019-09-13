package fpast2l

import (
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/o1egl/paseto"
)

var (
	zbase32 = base32.NewEncoding("ybndrfg8ejkmcpqxot1uwisza345h769").
		WithPadding(base32.NoPadding)

	referencePASETO = paseto.NewV2()
	sysPageSize     = os.Getpagesize()
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestEngineEncrypt(t *testing.T) {
	t.Parallel()

	k := randomBytes(make([]byte, KeySize))
	eng := New(k).WithFooter(randomString(32))

	for i, b := range [...][]byte{
		nil, {}, {0},
		randomBytes(make([]byte, 64)),
		randomBytes(make([]byte, 1<<10)),
	} {
		s := eng.Encrypt(b)
		r, f, err := rPASTDecrypt(k, s)

		if err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}

		if !bytes.Equal(r, b) {
			exp := hex.EncodeToString(r)
			act := hex.EncodeToString(b)
			t.Errorf("i=%d: expected r = Hex(%q), actual Hex(%q)", i, exp, act)
		}

		if f != eng.f {
			t.Errorf("i=%d: expected f = %q, actual %q", i, eng.f, f)
		}
	}
}

func TestEngineDecrypt(t *testing.T) {
	t.Parallel()

	k := randomBytes(make([]byte, KeySize))
	eng := New(k).WithFooter(randomString(32))

	for i, b := range [...][]byte{
		nil, {}, {0},
		randomBytes(make([]byte, 64)),
		randomBytes(make([]byte, 1<<10)),
	} {
		s := rPASTEncrypt(k, b, eng.f)

		r, err := eng.Decrypt(nil, s)
		if err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}

		if !bytes.Equal(r, b) {
			exp := hex.EncodeToString(b)
			act := hex.EncodeToString(r)
			t.Errorf("i=%d: expected r = Hex(%q), actual Hex(%q)", i, exp, act)
		}
	}
}

func BenchmarkEngineEncrypt(b *testing.B) {
	eng := New(randomBytes(make([]byte, KeySize)))
	B := randomBytes(make([]byte, 32, 128))
	bigB := randomBytes(make([]byte, sysPageSize, 2*sysPageSize))

	b.Run("TypicalPayload", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = eng.Encrypt(B)
		}
	})

	b.Run("LargePayload", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = eng.Encrypt(bigB)
		}
	})
}

func BenchmarkEngineDecrypt(b *testing.B) {
	k := randomBytes(make([]byte, KeySize))
	eng := New(k)
	s := rPASTEncrypt(k, randomBytes(make([]byte, 32)), "")
	bigS := rPASTEncrypt(k,
		randomBytes(make([]byte, sysPageSize)),
		randomString(32))
	p := make([]byte, 2*sysPageSize)[:0]

	b.Run("TypicalToken", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = eng.Decrypt(p, s)
		}
	})

	b.Run("LargeToken", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = eng.Decrypt(p, bigS)
		}
	})
}

func randomBytes(p []byte) (b []byte) {
	if _, err := rand.Read(p); nil != err {
		panic(err)
	}

	return p
}

func randomString(n int) (s string) {
	return zbase32.EncodeToString(
		randomBytes(make([]byte, zbase32.DecodedLen(n+1))),
	)[:n]
}

func copyBuffer(p []byte) (b []byte) {
	b = make([]byte, len(p))
	copy(b, p)
	return
}

func rPASTEncrypt(key, b []byte, f string) (s string) {
	_f := (interface{})(f)
	if 0 == len(f) {
		_f = nil
	}

	err := error(nil)
	if s, err = referencePASETO.Encrypt(key, b, _f); nil != err {
		panic(err)
	}

	return
}

func rPASTDecrypt(key []byte, s string) (b []byte, f string, err error) {
	_f := (interface{})(&f)
	_b := (interface{})(&b)
	err = referencePASETO.Decrypt(s, key, _b, _f)
	return
}
