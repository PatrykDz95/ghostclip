package app

import "ghostclip/internal/p2p"

// handles incoming clipboard sync messages
func (app *Application) handleClipboardSync(msg *p2p.Message) {
	if msg.Type != p2p.MsgTypeSync {
		return
	}

	content := msg.Payload.ClipboardContent
	if err := app.clipboard.Set(content); err != nil {
		app.logger.Error("Failed to set clipboard", "error", err)
		return
	}

	app.logger.Info("Clipboard synced", "size", len(content))
}

func (app *Application) startClipboardMonitoring() error {
	return app.clipboard.Watch(func(content string) {
		app.logger.Info("Local clipboard changed", "size", len(content))
		app.p2pMgr.BroadcastClipBoard(content)
	})
}
