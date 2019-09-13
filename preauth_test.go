package fpast2l

import (
	"testing"
)

func Test_paeinit(t *testing.T) {
	t.Parallel()
	p := new(pae)

	maxc := 0
	for i, c := range []int{0, 64, 32, 0} {
		if maxc < c {
			maxc = c
		}

		p.init(c)

		b := []byte(*p)
		if exp, act := minPAESize, len(b); exp != act {
			t.Fatalf("i=%d: expected len(b) = %d, actual %d", i, exp, act)
		}

		if exp, act := minPAESize+maxc, cap(b); exp != act {
			t.Fatalf("i=%d: expected cap(b) = %d, actual %d", i, exp, act)
		}

		j := 0
		if exp, act := uint64(3), le.Uint64(b[j:]); exp != act {
			t.Fatalf("i=%d: at index=%d: expected LE64(%d), actual LE64(%d)",
				i, j, exp, act)
		}

		j += 8
		if exp, act := uint64(headerSize), le.Uint64(b[j:]); exp != act {
			t.Fatalf("i=%d: at index=%d: expected LE64(%d), actual LE64(%d)",
				i, j, exp, act)
		}

		j += 8
		if exp, act := header, string(b[j:][:headerSize]); exp != act {
			t.Fatalf("i=%d: at index=%d, expected %q, actual %q", i, j, exp, act)
		}

		j += headerSize
		if exp, act := uint64(nonceSize), le.Uint64(b[j:]); exp != act {
			t.Fatalf("i=%d: at index=%d: expected LE64(%d), actual LE64(%d)",
				i, j, exp, act)
		}

		j += nonceSize
		if exp, act := uint64(0), le.Uint64(b[j:]); exp != act {
			t.Fatalf("i=%d: at index=%d: expected LE64(%d), actual LE64(%d)",
				i, j, exp, act)
		}
	}
}
