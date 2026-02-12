package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ghostclip/internal/p2p"

	"github.com/gen2brain/beeep"
	"github.com/sqweek/dialog"
)

func (app *Application) handleIncomingFile(senderName, fileName string, fileSize int64) (bool, string) {
	app.playNotificationSound()

	notificationTitle := "Incoming File Transfer"
	notificationMsg := fmt.Sprintf("%s wants to send you:\n%s (%.2f MB)",
		senderName, fileName, float64(fileSize)/(1024*1024))

	if err := beeep.Notify(notificationTitle, notificationMsg, ""); err != nil {
		app.logger.Warn("Failed to show notification", "error", err)
	}

	response := dialog.Message("%s wants to send you a file:\n\n%s\n\nSize: %.2f MB\n\nDo you want to accept?",
		senderName, fileName, float64(fileSize)/(1024*1024)).
		Title("Incoming File Transfer").
		YesNo()

	if !response {
		app.logger.Info("File transfer rejected by user", "file", fileName)
		app.playRejectionSound()
		return false, ""
	}

	app.logger.Info("File transfer accepted", "file", fileName)

	receivedDir := getReceivedFilesDir()
	if err := os.MkdirAll(receivedDir, 0755); err != nil {
		app.logger.Error("Failed to create directory", "error", err)
		return false, ""
	}

	savePath := filepath.Join(receivedDir, fileName)
	app.logger.Info("File will be saved to", "path", savePath)

	return true, savePath
}

func (app *Application) sendFileToDevice(deviceID string) {
	app.logger.Info("Preparing to send file", "device_id", deviceID)

	peers := app.p2pMgr.GetPeers()
	targetPeer := findPeer(peers, deviceID)
	if targetPeer == nil {
		app.logger.Error("Peer not found", "device_id", deviceID)
		return
	}

	filePath, err := app.getFilePathFromClipboard()
	if err != nil {
		app.logger.Warn("Clipboard does not contain a valid file path", "error", err)
		return
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		app.logger.Warn("File not found", "path", filePath, "error", err)
		return
	}

	app.logger.Info("Sending file",
		"file", filepath.Base(filePath),
		"size", fileInfo.Size(),
		"to", targetPeer.DeviceName)

	if err := app.p2pMgr.SendFile(deviceID, filePath); err != nil {
		app.logger.Error("Failed to send file", "error", err)
		return
	}

	app.logger.Info("File sent successfully", "file", filepath.Base(filePath))
}

func (app *Application) getFilePathFromClipboard() (string, error) {
	content, err := app.clipboard.Get()
	if err != nil {
		return "", fmt.Errorf("failed to get clipboard: %w", err)
	}

	filePath := strings.TrimSpace(content)
	filePath = strings.Trim(filePath, "\"") // Remove quotes (Windows adds them)

	return filePath, nil
}

func findPeer(peers []p2p.PeerInfo, deviceID string) *p2p.PeerInfo {
	for _, peer := range peers {
		if peer.DeviceID == deviceID {
			return &peer
		}
	}
	return nil
}
