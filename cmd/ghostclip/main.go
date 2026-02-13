package main

import (
	_ "embed"
	"io"
	"log"

	"github.com/getlantern/systray"
)

//go:embed assets/klip-48.png
var iconData []byte

func main() {
	// Suppress mdns warnings
	log.SetOutput(io.Discard)

	app := NewApplication()
	systray.Run(app.onReady, app.onExit)
}
