package internal

import (
	"net/http"

	"github.com/rs/zerolog"
	"github.com/zrhmn/fpast2l"
)

const n = fpast2l.KeySize

type (
	// App ...
	App interface {
		Start()
		Stop()
		Errors() <-chan error
	}

	_App struct {
		srv http.Server
		eng fpast2l.Engine
		log zerolog.Logger

		// state (access atomically):
		// 0: uninitialized
		// 1: initialized
		// 2: serving
		// 3: critical
		// 4: shutting down
		state uint32

		// error channel, initialize unbuffered
		errs chan error
	}
)

func app(c *config) App {
	app := _App{
		srv: http.Server{},
		log: c.logConfig.newLogger(),
		eng: fpast2l.Engine{},

		state: 1,
		errs:  make(chan error),
	}

	app.srv.Handler = &app
	return &app
}

func (app *_App) Start()               {}
func (app *_App) Stop()                {}
func (app *_App) Errors() <-chan error { return app.errs }
func (app *_App) ServeHTTP(_ http.ResponseWriter, _ *http.Request)

func (app *_App) addListeners(addrs []Addr) {
	for _, addr := range addrs {
		ln, err := addr.Listen()
		if nil != err {
			go func() { app.errs <- err }()
			continue
		}

		app.srv.Serve(ln)
	}
}
