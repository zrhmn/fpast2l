package internal

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"

	"github.com/rs/zerolog"
)

type config struct {
	*logConfig
	bindConfig []bindConfig
}

type logConfig struct {
	Level  zerolog.Level
	Output io.Writer
}

type bindConfig struct {
	TLS *tls.Config
	Network,
	Address string
}

func (c *logConfig) newLogger() zerolog.Logger {
	if nil == c || nil == c.Output {
		return zerolog.Nop()
	}

	return zerolog.New(c.Output).Level(c.Level).
		With().Timestamp().Logger()
}

func (c bindConfig) addListener(srv *http.Server) error {
	ln, err := net.Listen(c.Network, c.Address)
	if nil != err {
		return err
	}

	if nil != c.TLS {
		ln = tls.NewListener(ln, c.TLS)
	}

	return srv.Serve(ln)
}
