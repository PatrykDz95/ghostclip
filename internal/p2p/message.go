package p2p

import "time"

const (
	MsgTypeHello     = "hello"
	MsgTypeSync      = "sync"
	MsgTypeFileOffer = "file_offer"
)

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
	Version    string `json:"version,omitempty"`

	// MsgTypeSync clipboard content
	ClipboardContent string `json:"clipboard_content,omitempty"`

	// MsgTypeFileOffer
	FileName    string `json:"file_name,omitempty"`
	Size        int64  `json:"size,omitempty"`
	ContentHash string `json:"content_hash,omitempty"` // transfer ID
}
