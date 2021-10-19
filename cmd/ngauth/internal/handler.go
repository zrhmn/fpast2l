package internal

import (
	"encoding/base64"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/zrhmn/fpast2l"
)

var bytesPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, os.Getpagesize())
	},
}

type core struct {
	*http.Request
	http.ResponseWriter

	Epoch  time.Time
	Status int
}

func (c *core) Write(b []byte) (n int, err error) {
	w := c.ResponseWriter
	w.WriteHeader(c.Status)
	return w.Write(b)
}

func (c *core) Decrypt(eng *fpast2l.Engine) {
	const Bearer = "Bearer "
	auth := c.Request.Header.Get("Authorization")
	if len(Bearer) >= len(auth) {
		c.Status = http.StatusUnauthorized
		return
	}

	auth = auth[len(Bearer):]
	buf := bytesPool.Get().([]byte)
	defer func() { bytesPool.Put(buf[:0]) }()

	err := error(nil)
	if buf, err = eng.Decrypt(buf[:0], auth); nil != err {
		c.Status = http.StatusUnauthorized
		return
	}

	c.ResponseWriter.Header().Add(
		"Authorization", Bearer+base64.RawURLEncoding.EncodeToString(buf),
	)

	c.Status = http.StatusOK
}

func (app *_App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const bearer = "Bearer "
	c := core{Request: r, ResponseWriter: w, Epoch: time.Now()}
	c.Decrypt(&app.Engine)

	app.LogRequest(&c)
	c.Write(nil)
}
