package app

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
)

const deviceIDLength = 8

func getDefaultDeviceName() string {
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
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
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "ghostclip.log"
	}

	return filepath.Join(logDir, "ghostclip.log")
}

func getReceivedFilesDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "received-files"
	}
	return filepath.Join(home, "Ghostclip", "Received Files")
}

func generateDeviceID() string {
	b := make([]byte, deviceIDLength)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", os.Getpid())
	}
	return fmt.Sprintf("%x", b)
}

// checks for required system dependencies
func checkDependencies(logger *slog.Logger) bool {
	if runtime.GOOS != "linux" {
		return true
	}

	_, xclipErr := os.Stat("/usr/bin/xclip")
	_, xselErr := os.Stat("/usr/bin/xsel")

	if xclipErr != nil && xselErr != nil {
		logger.Error("Neither xclip nor xsel found. Please install: sudo apt install xclip")
		return false
	}

	return true
}
