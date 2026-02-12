package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"ghostclip/internal/clipboard"
	"ghostclip/internal/p2p"
	"ghostclip/internal/security"

	"github.com/getlantern/systray"
)

const (
	version     = "1.0.0"
	defaultPort = 9876
)

type Application struct {
	logger    *slog.Logger
	p2pMgr    *p2p.Manager
	discovery *p2p.Discovery
	clipboard clipboard.Clipboard
	ctx       context.Context
	cancel    context.CancelFunc

	ui *UI
}

func NewApplication() *Application {
	return &Application{
		ui: &UI{
			peerMenuItems:   make(map[string]*systray.MenuItem),
			peerCancelFuncs: make(map[string]context.CancelFunc),
		},
	}
}

func (app *Application) onReady() {
	systray.SetIcon(iconData)
	systray.SetTitle("Ghostclip")
	systray.SetTooltip("Ghostclip - Starting...")

	app.buildMenu()
	go app.startBackend()
}

func (app *Application) onExit() {
	if app.cancel != nil {
		app.cancel()
	}
	if app.logger != nil {
		app.logger.Info("Ghostclip application stopped")
	}
}

func (app *Application) startBackend() {
	cfg := parseFlags()

	if err := app.initLogger(cfg.Verbose); err != nil {
		return
	}

	if cfg.DeviceName == "" {
		cfg.DeviceName = getDefaultDeviceName()
	}

	deviceID := generateDeviceID()

	app.logger.Info("Starting Ghostclip",
		"version", version,
		"device", cfg.DeviceName,
		"device_id", deviceID,
		"os", runtime.GOOS,
	)

	if err := app.initializeComponents(cfg, deviceID); err != nil {
		app.logger.Error("Failed to initialize", "error", err)
		app.updateStatus("Error: " + err.Error())
		return
	}

	if err := app.startServices(cfg, deviceID); err != nil {
		app.logger.Error("Failed to start services", "error", err)
		return
	}

	app.updateStatus("Running")
	systray.SetTooltip("Ghostclip - Ready")
	app.updatePeerMenu()

	app.logger.Info("Ghostclip started successfully")
}

func (app *Application) initLogger(verbose bool) error {
	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}

	logFile := getLogPath()
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		file = os.Stderr
	}

	app.logger = slog.New(slog.NewTextHandler(file, &slog.HandlerOptions{
		Level: logLevel,
	}))

	return nil
}

func (app *Application) initializeComponents(cfg *Config, deviceID string) error {
	app.updateStatus("Checking dependencies")
	if !checkDependencies(app.logger) {
		return fmt.Errorf("missing dependencies")
	}

	app.updateStatus("Generating certificates")
	certDir := getCertDir()
	cert, err := security.GenerateSelfSignedCert(certDir, deviceID)
	if err != nil {
		return fmt.Errorf("certificate generation failed: %w", err)
	}
	tlsConfig := security.CreateTLSConfig(cert)

	app.updateStatus("Initializing clipboard")
	cb, err := clipboard.New()
	if err != nil {
		return fmt.Errorf("clipboard initialization failed: %w", err)
	}
	app.clipboard = cb

	app.updateStatus("Starting network")
	app.p2pMgr = p2p.NewManager(deviceID, cfg.DeviceName, cfg.Port, tlsConfig, app.logger)

	app.p2pMgr.SetOnMessage(app.handleClipboardSync)
	app.p2pMgr.SetOnFileReceive(app.handleIncomingFile)

	return nil
}

func (app *Application) startServices(cfg *Config, deviceID string) error {
	if err := app.p2pMgr.Listen(); err != nil {
		return fmt.Errorf("listener start failed: %w", err)
	}

	app.ctx, app.cancel = context.WithCancel(context.Background())
	app.discovery = p2p.NewDiscovery(
		deviceID,
		cfg.DeviceName,
		cfg.Port,
		app.handlePeerDiscovered,
	)

	go func() {
		if err := app.discovery.Advertise(app.ctx); err != nil {
			app.logger.Error("Advertisement error", "error", err)
		}
	}()

	go func() {
		if err := app.discovery.Discover(app.ctx); err != nil {
			app.logger.Error("Discovery error", "error", err)
		}
	}()

	if cfg.PeerAddr != "" {
		go app.connectToManualPeer(cfg.PeerAddr)
	}

	go app.startClipboardMonitoring()

	return nil
}
