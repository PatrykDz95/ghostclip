package main

import "github.com/gen2brain/beeep"

func (app *Application) playNotificationSound() {
	if err := beeep.Beep(beeep.DefaultFreq, beeep.DefaultDuration); err != nil {
		app.logger.Warn("Failed to play notification sound", "error", err)
	}
}

func (app *Application) playRejectionSound() {
	if err := beeep.Beep(400, 200); err != nil {
		app.logger.Warn("Failed to play rejection sound", "error", err)
	}
}
