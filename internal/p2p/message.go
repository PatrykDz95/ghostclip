package p2p

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	MsgTypeHello      = "hello"
	MsgTypeSync       = "sync"
	MsgTypeFileOffer  = "file_offer"
	MsgTypeFileAccept = "file_accept"
)

// Magic number to identify file transfer data
const FileTransferMagic = 0x47435446 // "GCTF" - GhostClip Transfer File

type Message struct {
	Type      string    `json:"type"`
	DeviceID  string    `json:"device_id"`
	Timestamp time.Time `json:"timestamp"`
	Payload   *Payload  `json:"payload,omitempty"`
}

type Payload struct {
	// MsgTypeHello device info
	DeviceName string `json:"device_name,omitempty"`
	OS         string `json:"os,omitempty"`

	// MsgTypeSync clipboard content
	ClipboardContent string `json:"clipboard_content,omitempty"`

	// MsgTypeFileOffer
	FileName    string `json:"file_name,omitempty"`
	Size        int64  `json:"size,omitempty"`
	ContentHash string `json:"content_hash,omitempty"` // transfer ID
}

// writes the binary file header: [magic:4][size:8]
func WriteFileHeader(w io.Writer, size int64) error {
	// Write magic number (4 bytes)
	if err := binary.Write(w, binary.BigEndian, uint32(FileTransferMagic)); err != nil {
		return fmt.Errorf("failed to write magic: %w", err)
	}
	// Write file size (8 bytes)
	if err := binary.Write(w, binary.BigEndian, size); err != nil {
		return fmt.Errorf("failed to write size: %w", err)
	}
	return nil
}

// reads the binary file header and returns the file size
func ReadFileHeader(r io.Reader) (int64, error) {
	// Read magic number (4 bytes)
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return 0, fmt.Errorf("failed to read magic: %w", err)
	}
	if magic != FileTransferMagic {
		return 0, fmt.Errorf("invalid file transfer magic: got 0x%x, expected 0x%x", magic, FileTransferMagic)
	}
	// Read file size (8 bytes)
	var size int64
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return 0, fmt.Errorf("failed to read size: %w", err)
	}
	if size < 0 {
		return 0, fmt.Errorf("invalid file size: %d", size)
	}
	return size, nil
}
