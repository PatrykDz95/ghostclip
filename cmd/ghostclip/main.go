package main

import (
	_ "embed"
	"io"
	"log"

	"ghostclip/internal/app"

	"github.com/getlantern/systray"
)

//go:embed assets/klip-48.png
var iconData []byte

func main() {
	// Suppress mdns warnings
	log.SetOutput(io.Discard)

	application := app.NewApplication(iconData)
	systray.Run(application.OnReady, application.OnExit)
}
