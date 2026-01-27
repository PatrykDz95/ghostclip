package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"ghostclip/internal/clipboard"
	"ghostclip/internal/p2p"
	"ghostclip/internal/security"
)

const Version = "1.0.0"

func getDefaultName() string {
	hostname, err := os.Hostname()
	if err == nil && hostname != "" {
		return hostname
	}
	return runtime.GOOS + "-device"
}

// getCertDir returns the default certificate directory
func getCertDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ghostclip/certs"
	}
	return filepath.Join(home, ".ghostclip", "certs")
}

// generateDeviceID generates a random device ID (16 hex characters)
func generateDeviceID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func main() {
	// Suppress mDNS IPv6 warnings
	log.SetOutput(io.Discard)

	// Parse command line flags
	deviceName := flag.String("name", getDefaultName(), "Device name")
	port := flag.Int("port", 9876, "P2P port")
	certDir := flag.String("certs", getCertDir(), "Certificate directory")
	verbose := flag.Bool("v", false, "Verbose logging")
	flag.Parse()

	// Configure logger
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	deviceID := generateDeviceID()

	logger.Info("Starting Clipboard Sync",
		"version", Version,
		"device", *deviceName,
		"device_id", deviceID,
		"os", runtime.GOOS,
	)

	logger.Info("Checking TLS certificates", "dir", *certDir)
	cert, err := security.GenerateSelfSignedCert(*certDir, deviceID)
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	tlsConfig := security.CreateTLSConfig(cert)
	logger.Info("🔒 TLS 1.3 enabled - all traffic encrypted",
		"cipher", "AES-256-GCM",
	)

	cb, err := clipboard.New()
	if err != nil {
		log.Fatalf("Failed to initialize clipboard: %v", err)
	}
	logger.Info("Clipboard initialized", "platform", runtime.GOOS)

	// Initialize P2P manager
	p2pMgr := p2p.NewManager(deviceID, *deviceName, *port, tlsConfig, logger)

	// Set message callback for incoming clipboard data
	p2pMgr.SetOnMessage(func(msg *p2p.Message) {
		if msg.Type == p2p.MsgTypeSync {
			content := msg.Payload.ClipboardContent
			logger.Info("Clipboard received",
				"from", msg.DeviceID,
				"size", len(content),
			)

			if err := cb.Set(content); err != nil {
				logger.Error("Failed to set clipboard", "error", err)
			} else {
				logger.Debug("Clipboard updated")
			}
		}
	})

	// Start TLS listener
	if err := p2pMgr.Listen(); err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}

	// Start mDNS discovery
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	discovery := p2p.NewDiscovery(deviceID, *deviceName, *port, func(peerID, addr string) {
		logger.Info("Discovered peer", "peer_id", peerID, "addr", addr)
		if err := p2pMgr.Connect(peerID, addr); err != nil {
			logger.Error("Failed to connect", "peer", peerID, "error", err)
		}
	})

	go func() {
		if err := discovery.Advertise(ctx); err != nil {
			logger.Error("Discovery advertise failed", "error", err)
		}
	}()

	go func() {
		if err := discovery.Discover(ctx); err != nil {
			logger.Error("Discovery scan failed", "error", err)
		}
	}()

	logger.Info("mDNS discovery started")

	// Start clipboard monitoring
	go func() {
		logger.Info("Clipboard monitoring started")
		cb.Watch(func(content string) {
			logger.Info("Local clipboard changed",
				"size", len(content),
			)
			p2pMgr.BroadcastClipBoard(content)
		})
	}()

	// Log startup success
	logger.Info("🚀 Clipboard Sync is running!")
	logger.Info("🔒 Secured with TLS 1.3 (AES-256-GCM)")
	logger.Info("Press Ctrl+C to stop")

	// Wait for interrupt signal for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down...")
	cancel()
}
