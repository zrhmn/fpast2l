package internal

import (
	"io"

	"github.com/rs/zerolog"
	"github.com/zrhmn/fpast2l"
)

const n = fpast2l.KeySize

// Config ...
type Config struct {
	Log struct {
		Level  zerolog.Level
		Output io.Writer
	}

	Bind struct {
		Network string
		Address string
	}

	PASETO struct {
		Key    [n]byte
		Footer string
	}
}
