package p2p

import "time"

const (
	MsgTypeHello = "hello"
	MsgTypeSync  = "sync"
)

type Message struct {
	Type      string    `json:"type"`
	DeviceID  string    `json:"device_id"`
	Timestamp time.Time `json:"timestamp"`
	Payload   *Payload  `json:"payload,omitempty"`
}

type Payload struct {
	// MsgTypeSync
	ClipboardContent string `json:"clipboard_content,omitempty"`
	ContentHash      string `json:"content_hash,omitempty"`

	// MsgTypeHello
	DeviceName string `json:"device_name,omitempty"`
	OS         string `json:"os,omitempty"`
	Version    string `json:"version,omitempty"`
}
