package internal

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/zrhmn/fpast2l"
)

func _() {
	_ = App(&_App{})
}

// App ...
type App interface {
	Start()
	Stop()
	Errs() <-chan error
}

type _App struct {
	Config
	net.Listener
	http.Server
	fpast2l.Engine
	zerolog.Logger

	errors chan error
}

// NewApp ...
func NewApp(c Config) App {
	app := _App{
		errors: make(chan error),
		Logger: zerolog.Nop(),
	}

	app.Engine = fpast2l.
		New(c.PASETO.Key[:]).
		WithFooter(c.PASETO.Footer)

	app.Server.Handler = &app // app.ServeHTTP implements http.Handler

	if nil != c.Log.Output {
		app.Logger = zerolog.New(c.Log.Output).
			With().Timestamp().Logger().
			With().Str("unit", "app").Logger()

		app.Logger.Level(c.Log.Level)
	}

	// set default listen config before it is consumed by app.Start
	if 0 == len(c.Bind.Network) {
		c.Bind.Network = "tcp"
		if 0 == len(c.Bind.Address) {
			c.Bind.Address = ":"
		}
	}

	app.Config = c
	return &app
}

func (app *_App) Start() {
	var err error
	app.LogEvent("INIT").Send()

	if app.Listener, err = net.Listen(
		app.Config.Bind.Network,
		app.Config.Bind.Address,
	); nil != err {
		app.errors <- err
		close(app.errors) // closing app.errors marks app termination
		return
	}

	go func() {
		app.LogEvent("LISTEN").
			Str("network", app.Listener.Addr().Network()).
			Str("addr", app.Listener.Addr().String()).
			Send()

		if err := app.Serve(app.Listener); err != nil {
			if err != http.ErrServerClosed {
				app.errors <- err
			}
		}

		app.LogEvent("CLOSE").Send()
	}()
}

func (app *_App) Stop() {
	var err error
	ctx, cfn := context.WithTimeout(context.Background(), 5*time.Second)
	defer cfn()

	if err = app.Server.Shutdown(ctx); nil != err {
		app.errors <- err
	}

	// app.Server.Serve closes app.Listener as well.

	app.LogEvent("STOP").Send()
	close(app.errors) // closing app.errors marks app termination
}

func (app *_App) Errs() <-chan error { return app.errors }

func (app *_App) LogEvent(ev string) *zerolog.Event {
	return app.Logger.Debug().Str("event", ev)
}

func (app *_App) LogRequest(c *core) {
	app.LogEvent("REQUEST").
		Str("remoteAddr", c.RemoteAddr).
		Str("method", c.Method).
		Str("path", c.URL.Path).
		Str("proto", c.Proto).
		Int("status", c.Status).
		Dur("reponseTime", time.Since(c.Epoch)).
		Send()
}
