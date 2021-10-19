package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"

	"github.com/rs/zerolog"
	"github.com/zrhmn/fpast2l/cmd/ngauth/internal"
)

var (
	ec     int
	errlog zerolog.Logger
)

func init() {
	// set up the main error log
	errlog = zerolog.New(os.Stderr).
		With().Timestamp().Logger().
		With().Str("unit", fmt.Sprintf("main/%d", os.Getpid())).Logger()

	errlog.Level(zerolog.InfoLevel)
}

func main() {
	// IMPORTANT:
	// chans must be unbuffered, so the receives in main and handleSignal block
	// indefinitely.
	sigchan := make(chan os.Signal)
	signal.Notify(sigchan, os.Interrupt, os.Kill)

	finchan := make(chan struct{})

	cfg := internal.Config{} // call ParseConfig instead
	cfg.Log.Output = os.Stdout

	if _, err := rand.Read(cfg.PASETO.Key[:]); nil != err {
		errlog.Fatal().Err(err).Send()
	}

	app := internal.NewApp(cfg)
	go handleAppErrs(finchan, app)
	go handleSignal(sigchan, app)

	app.Start()
	<-finchan // wait for finish and then return (exit successfully)
}

func handleSignal(sigchan <-chan os.Signal, app internal.App) {
	sig := <-sigchan // first sig
	errlog.Info().Str("signal", sig.String()).Send()

	go app.Stop() // start teardown

	sig = <-sigchan // second sig
	os.Exit(127)    // forced exit
}

func handleAppErrs(finchan chan<- struct{}, app internal.App) {
	errchan := app.Errs()
	err := error(nil)
	for err = range errchan {
		errlog.Error().Err(err).Send()
	}

	if err != nil { // last error before errchan was closed
		os.Exit(2)
	}

	// fin when errchan is closed
	finchan <- struct{}{}
}
