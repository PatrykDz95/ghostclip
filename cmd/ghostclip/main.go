package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"ghostclip/internal/clipboard"
	"ghostclip/internal/p2p"
	"ghostclip/internal/security"

	"github.com/getlantern/systray"
)

//go:embed assets/ghostclip_logox48.ico
var iconData []byte

const Version = "1.0.0"

var (
	logger    *slog.Logger
	p2pMgr    *p2p.Manager
	discovery *p2p.Discovery
	cb        clipboard.Clipboard
	ctx       context.Context
	cancel    context.CancelFunc

	// Menu items
	mStatus       *systray.MenuItem
	mDevices      *systray.MenuItem
	peerMenuItems map[string]*systray.MenuItem
)

func main() {
	// Suppress mdns warnings
	log.SetOutput(io.Discard)

	// Run as tray application
	systray.Run(onReady, onExit)
}

func onReady() {
	// Set icon and title
	systray.SetIcon(iconData)
	systray.SetTitle("Ghostclip")
	systray.SetTooltip("Ghostclip - Starting...")

	// Build menu
	buildMenu()

	// Start backend in goroutine
	go startBackend()
}

func buildMenu() {
	// Status (read-only)
	mStatus = systray.AddMenuItem("Starting...", "Current status")
	mStatus.Disable()

	// Device count
	mDevices = systray.AddMenuItem("Devices: 0", "Connected devices")

	// Initialize peer menu items map
	peerMenuItems = make(map[string]*systray.MenuItem)

	systray.AddSeparator()

	// About
	mAbout := systray.AddMenuItem("About Ghostclip", "About this application")

	// Quit
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "Exit Ghostclip")

	// Handle menu clicks
	go func() {
		for {
			select {
			case <-mAbout.ClickedCh:
				showAbout()
			case <-mQuit.ClickedCh:
				systray.Quit()
			}
		}
	}()
}

func startBackend() {
	// Parse flags (even though we're in tray mode)
	verbose := flag.Bool("v", false, "verbose logging")
	deviceName := flag.String("name", "", "device name")
	port := flag.Int("port", 9876, "listening port")
	peerAddr := flag.String("peer", "", "manual peer address")
	flag.Parse()

	// Setup logger
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}

	logFile := getLogPath()
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		file = os.Stderr
	}

	// for debuging only. Remove in production
	//multiWriter := io.MultiWriter(file, os.Stdout)
	//logger = slog.New(slog.NewTextHandler(multiWriter, &slog.HandlerOptions{
	//	Level: logLevel,
	//}))

	logger = slog.New(slog.NewTextHandler(file, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Get device info
	if *deviceName == "" {
		*deviceName = getDefaultName()
	}

	certDir := getCertDir()
	deviceID := generateDeviceID()

	logger.Info("Starting Ghostclip",
		"version", Version,
		"device", *deviceName,
		"device_id", deviceID,
		"os", runtime.GOOS,
	)

	updateStatus("Checking dependencies...")

	// Check dependencies (Linux only)
	if !checkLinuxDependencies(logger) {
		updateStatus("Error: Missing dependencies")
		systray.SetTooltip("Ghostclip - Error: Install xclip")
		return
	}

	// Initialize TLS
	updateStatus("Generating certificates...")
	cert, err := security.GenerateSelfSignedCert(certDir, deviceID)
	if err != nil {
		updateStatus("Certificate error")
		logger.Error("Failed to generate certificate", "error", err)
		return
	}

	tlsConfig := security.CreateTLSConfig(cert)

	// Initialize clipboard
	updateStatus("Initializing clipboard...")
	cb, err = clipboard.New()
	if err != nil {
		updateStatus("Clipboard error")
		logger.Error("Failed to initialize clipboard", "error", err)
		return
	}

	// Initialize P2P
	updateStatus("Starting network...")
	p2pMgr = p2p.NewManager(deviceID, *deviceName, *port, tlsConfig, logger)

	// Set message callback
	p2pMgr.SetOnMessage(func(msg *p2p.Message) {
		if msg.Type == p2p.MsgTypeSync {
			content := msg.Payload.ClipboardContent
			if err := cb.Set(content); err != nil {
				logger.Error("Failed to set clipboard", "error", err)
			} else {
				logger.Info("Clipboard synced", "size", len(content))
			}
		}
	})

	// Start listener
	if err := p2pMgr.Listen(); err != nil {
		updateStatus("Network error")
		logger.Error("Failed to start listener", "error", err)
		return
	}

	// Start discovery
	ctx, cancel = context.WithCancel(context.Background())

	discovery = p2p.NewDiscovery(deviceID, *deviceName, *port, func(peerID, addr string) {
		logger.Info("Discovered peer", "peer_id", peerID, "addr", addr)
		if err := p2pMgr.Connect(peerID, addr); err != nil {
			logger.Error("Failed to connect to peer", "peer", peerID, "error", err)
		} else {
			updatePeerMenu()
			//updateDeviceCount()
		}
	})

	go func() {
		err := discovery.Advertise(ctx)
		if err != nil {
			logger.Error("Advertisement error", "error", err)
		}
	}()
	go func() {
		err := discovery.Discover(ctx)
		if err != nil {
			logger.Error("Discovery error", "error", err)
		}
	}()

	// Manual peer if specified
	if *peerAddr != "" {
		go func() {
			logger.Info("Connecting to manual peer", "addr", *peerAddr)
			if err := p2pMgr.Connect("manual-peer", *peerAddr); err != nil {
				logger.Error("Failed to connect to manual peer", "error", err)
			}
		}()
	}

	// Start clipboard monitoring
	go func() {
		cb.Watch(func(content string) {
			logger.Info("Local clipboard changed", "size", len(content))
			p2pMgr.BroadcastClipBoard(content)
		})
	}()

	updateStatus("Running")
	systray.SetTooltip("Ghostclip - Ready")
	updatePeerMenu()

	logger.Info("Ghostclip started successfully")
}

func updateStatus(status string) {
	if mStatus != nil {
		mStatus.SetTitle(status)
	}
}

func showAbout() {
	logger.Info("About clicked")
	// TODO: Show native dialog or notification
	fmt.Printf("Ghostclip v%s\nSecure P2P clipboard sync\n", Version)
}

func onExit() {
	if cancel != nil {
		cancel()
	}
	if logger != nil {
		logger.Info("Ghostclip stopped")
	}
}

// Helper functions
func getDefaultName() string {
	hostname, err := os.Hostname()
	if err == nil && hostname != "" {
		return hostname
	}
	return runtime.GOOS + "-device"
}

func getCertDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".clipboard-sync/certs"
	}
	return filepath.Join(home, ".clipboard-sync", "certs")
}

func getLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "ghostclip.log"
	}
	logDir := filepath.Join(home, ".clipboard-sync")
	os.MkdirAll(logDir, 0755)
	return filepath.Join(logDir, "ghostclip.log")
}

func generateDeviceID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func checkLinuxDependencies(logger *slog.Logger) bool {
	if runtime.GOOS != "linux" {
		return true
	}

	// Check for xclip or xsel
	_, xclipErr := os.Stat("/usr/bin/xclip")
	_, xselErr := os.Stat("/usr/bin/xsel")

	if xclipErr != nil && xselErr != nil {
		logger.Error("Neither xclip nor xsel found. Please install: sudo apt install xclip")
		return false
	}

	return true
}

func updatePeerMenu() {
	if mDevices == nil || p2pMgr == nil {
		return
	}

	peers := p2pMgr.GetPeers()
	count := len(peers)

	// Update title and tooltip
	updateDevicesTitle(count)

	// Clear old submenu items
	clearPeerMenuItems()

	// Add submenu items for each peer
	if count == 0 {
		addNoDevicesItem()
	} else {
		addPeerItems(peers)
	}
}

func updateDevicesTitle(count int) {
	switch count {
	case 0:
		mDevices.SetTitle("Devices: 0 (searching...)")
		systray.SetTooltip("Ghostclip - Searching for devices")
	case 1:
		mDevices.SetTitle("Devices: 1 connected")
		systray.SetTooltip("Ghostclip - 1 device connected")
	default:
		mDevices.SetTitle(fmt.Sprintf("Devices: %d connected", count))
		systray.SetTooltip(fmt.Sprintf("Ghostclip - %d devices connected", count))
	}
}

func clearPeerMenuItems() {
	for deviceID, item := range peerMenuItems {
		item.Hide()
		delete(peerMenuItems, deviceID)
	}
}

func addNoDevicesItem() {
	noDevices := mDevices.AddSubMenuItem("No devices found", "")
	noDevices.Disable()
	peerMenuItems["_no_devices"] = noDevices
}

func addPeerItems(peers []p2p.PeerInfo) {
	for _, peer := range peers {
		item := mDevices.AddSubMenuItem(peer.DeviceName, fmt.Sprintf("Send file to %s (%s)", peer.DeviceName, peer.Address))
		peerMenuItems[peer.DeviceID] = item
		go handlePeerClick(peer.DeviceID, item)
	}
}

func handlePeerClick(deviceID string, item *systray.MenuItem) {
	for {
		<-item.ClickedCh
		logger.Info("Peer clicked", "device_id", deviceID)
		sendFileToDevice(deviceID)
	}
}

func sendFileToDevice(deviceID string) {
	logger.Info("Preparing to send file", "device_id", deviceID)

	//Find peer (for name to logs/notifications)
	peers := p2pMgr.GetPeers()
	var targetPeer *p2p.PeerInfo
	for _, peer := range peers {
		if peer.DeviceID == deviceID {
			targetPeer = &peer
			break
		}
	}

	if targetPeer == nil {
		logger.Error("Peer not found", "device_id", deviceID)
		return
	}

	//Get clipboard content (file path)
	content, err := cb.Get()
	if err != nil {
		logger.Error("Failed to get clipboard", "error", err)
		return
	}

	filePath := strings.TrimSpace(content)

	// Check if file exists
	// Remove quotes (Windows "Copy as path" adds them)
	filePath = strings.Trim(filePath, "\"")
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		logger.Warn("Clipboard is not a valid file path", "content", filePath)
		return
	}

	logger.Info("Sending file",
		"file", filepath.Base(filePath),
		"size", fileInfo.Size(),
		"to", targetPeer.DeviceName)

	err = p2pMgr.SendFile(deviceID, filePath)

	if err != nil {
		logger.Error("Failed to send file", "error", err)
		return
	}

	logger.Info("File sent successfully", "file", filepath.Base(filePath))
}
