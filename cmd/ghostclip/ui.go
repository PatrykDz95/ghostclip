package main

import (
	"context"
	"fmt"
	"sync"

	"ghostclip/internal/p2p"

	"github.com/getlantern/systray"
)

type UI struct {
	status  *systray.MenuItem
	devices *systray.MenuItem

	mu              sync.RWMutex
	peerMenuItems   map[string]*systray.MenuItem
	peerCancelFuncs map[string]context.CancelFunc
}

func (app *Application) buildMenu() {
	app.ui.status = systray.AddMenuItem("Starting...", "Current status")
	app.ui.status.Disable()

	app.ui.devices = systray.AddMenuItem("Devices: 0", "Connected devices")

	systray.AddSeparator()

	mAbout := systray.AddMenuItem("About Ghostclip", "About this application")

	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "Exit Ghostclip")

	go app.handleMenuClicks(mAbout, mQuit)
}

func (app *Application) handleMenuClicks(mAbout, mQuit *systray.MenuItem) {
	for {
		select {
		case <-mAbout.ClickedCh:
			app.showAbout()
		case <-mQuit.ClickedCh:
			systray.Quit()
		}
	}
}

func (app *Application) updateStatus(status string) {
	if app.ui.status != nil {
		app.ui.status.SetTitle(status)
	}
}

func (app *Application) updatePeerMenu() {
	if app.ui.devices == nil || app.p2pMgr == nil {
		return
	}

	peers := app.p2pMgr.GetPeers()
	count := len(peers)

	app.updateDevicesTitle(count)
	app.clearPeerMenuItems()

	if count == 0 {
		app.addNoDevicesItem()
	} else {
		app.addPeerItems(peers)
	}
}

func (app *Application) updateDevicesTitle(count int) {
	var title, tooltip string

	switch count {
	case 0:
		title = "Devices: 0 (searching...)"
		tooltip = "Ghostclip - Searching for devices"
	case 1:
		title = "Devices: 1 connected"
		tooltip = "Ghostclip - 1 device connected"
	default:
		title = fmt.Sprintf("Devices: %d connected", count)
		tooltip = fmt.Sprintf("Ghostclip - %d devices connected", count)
	}

	app.ui.devices.SetTitle(title)
	systray.SetTooltip(tooltip)
}

func (app *Application) clearPeerMenuItems() {
	app.ui.mu.Lock()
	defer app.ui.mu.Unlock()

	// Cancel all running goroutines first
	for deviceID, cancel := range app.ui.peerCancelFuncs {
		cancel()
		delete(app.ui.peerCancelFuncs, deviceID)
	}

	// Then clear menu items
	for deviceID, item := range app.ui.peerMenuItems {
		item.Hide()
		delete(app.ui.peerMenuItems, deviceID)
	}
}

// adds a disabled "no devices" placeholder
func (app *Application) addNoDevicesItem() {
	noDevices := app.ui.devices.AddSubMenuItem("No devices found", "")
	noDevices.Disable()

	app.ui.mu.Lock()
	defer app.ui.mu.Unlock()
	app.ui.peerMenuItems["_no_devices"] = noDevices
}

func (app *Application) addPeerItems(peers []p2p.PeerInfo) {
	for _, peer := range peers {
		tooltip := fmt.Sprintf("Send file to %s (%s)", peer.DeviceName, peer.Address)
		item := app.ui.devices.AddSubMenuItem(peer.DeviceName, tooltip)

		// Create cancellable context for this peer's goroutine
		ctx, cancel := context.WithCancel(context.Background())

		app.ui.mu.Lock()
		app.ui.peerMenuItems[peer.DeviceID] = item
		app.ui.peerCancelFuncs[peer.DeviceID] = cancel
		app.ui.mu.Unlock()

		go app.handlePeerClick(ctx, peer.DeviceID, item)
	}
}

func (app *Application) handlePeerClick(ctx context.Context, deviceID string, item *systray.MenuItem) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-item.ClickedCh:
			app.logger.Info("Peer clicked", "device_id", deviceID)
			app.sendFileToDevice(deviceID)
		}
	}
}

func (app *Application) showAbout() {
	app.logger.Info("About clicked")
	fmt.Printf("Ghostclip v%s\nSecure P2P clipboard sync\n", version)
}
