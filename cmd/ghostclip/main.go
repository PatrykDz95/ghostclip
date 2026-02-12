package main

import (
	_ "embed"
	"io"
	"log"

	"github.com/getlantern/systray"
)

//go:embed assets/ghostclip_logox48.ico
var iconData []byte

func main() {
	// Suppress mdns warnings
	log.SetOutput(io.Discard)

	app := NewApplication()
	systray.Run(app.onReady, app.onExit)
}
