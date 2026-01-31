package p2p

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type Manager struct {
	deviceID   string
	deviceName string
	port       int
	peers      map[string]*Peer
	mu         sync.RWMutex
	onMessage  func(*Message)
	lastHash   string
	tlsConfig  *tls.Config
	logger     *slog.Logger
}

func NewManager(deviceID, deviceName string, port int, tlsConfig *tls.Config, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}

	return &Manager{
		deviceID:   deviceID,
		deviceName: deviceName,
		port:       port,
		peers:      make(map[string]*Peer),
		tlsConfig:  tlsConfig,
		logger:     logger,
	}
}

// SetOnMessage sets the callback for incoming messages
func (m *Manager) SetOnMessage(callback func(*Message)) {
	m.onMessage = callback
}

// Listen starts the TLS listener for incoming connections
func (m *Manager) Listen() error {
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", m.port), m.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener: %w", err)
	}

	m.logger.Info("TLS listener started",
		"port", m.port,
		"tls_version", "1.3",
	)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				m.logger.Error("Accept error", "error", err)
				continue
			}

			tlsConn := conn.(*tls.Conn)

			m.logger.Debug("TLS connection accepted",
				"remote", conn.RemoteAddr(),
				"cipher", cipherSuiteName(tlsConn.ConnectionState().CipherSuite),
			)

			go m.handleConnection(tlsConn, false)
		}
	}()

	return nil
}

// Connect establishes a TLS connection to a peer
func (m *Manager) Connect(deviceID, address string) error {
	m.mu.RLock()
	_, exists := m.peers[deviceID]
	m.mu.RUnlock()

	if exists {
		return nil // already connected
	}

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, m.tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}

	state := conn.ConnectionState()
	m.logger.Info("TLS connection established",
		"peer", deviceID,
		"tls_version", tlsVersionName(state.Version),
		"cipher", cipherSuiteName(state.CipherSuite),
	)

	return m.handleConnection(conn, true)
}

func (m *Manager) handleConnection(conn net.Conn, initiator bool) error {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	// send HELLO if initiator
	if initiator {
		hello := &Message{
			Type:      MsgTypeHello,
			DeviceID:  m.deviceID,
			Timestamp: time.Now(),
			Payload: &Payload{
				DeviceName: m.deviceName,
				OS:         runtime.GOOS,
				Version:    "1.0.0", // TODO check if needed
			},
		}
		if err := encoder.Encode(hello); err != nil {
			conn.Close()
			return fmt.Errorf("failed to send hello: %w", err)
		}
	}

	// receive HELLO
	var msg Message
	if err := decoder.Decode(&msg); err != nil {
		conn.Close()
		return fmt.Errorf("failed to receive hello: %w", err)
	}

	// If it's a file offer, handle it immediately
	if msg.Type == MsgTypeFileOffer {
		m.logger.Info("Data channel opened for file", "name", msg.Payload.FileName)
		m.sendFileAccept(conn, "") // TODO for now accept automatically
		return m.receiveBinaryFile(conn, decoder, msg.Payload.FileName, msg.Payload.Size)
	}

	if msg.Type != MsgTypeHello {
		conn.Close()
		return fmt.Errorf("expected hello, got %s", msg.Type)
	}

	peer := &Peer{
		DeviceID:   msg.DeviceID,
		DeviceName: msg.Payload.DeviceName,
		OS:         msg.Payload.OS,
		Address:    conn.RemoteAddr().String(),
		Conn:       conn,
		LastSeen:   time.Now(),
	}

	m.mu.Lock()
	m.peers[msg.DeviceID] = peer
	m.mu.Unlock()

	m.logger.Info("Peer connected",
		"device_name", peer.DeviceName,
		"device_id", peer.DeviceID,
		"os", peer.OS,
	)

	// send HELLO if not initiator
	if !initiator {
		hello := &Message{
			Type:      MsgTypeHello,
			DeviceID:  m.deviceID,
			Timestamp: time.Now(),
			Payload: &Payload{
				DeviceName: m.deviceName,
				OS:         runtime.GOOS,
				Version:    "1.0.0",
			},
		}
		encoder.Encode(hello)
	}

	for {
		var mMsg Message
		if err := decoder.Decode(&mMsg); err != nil {
			break
		}
		if mMsg.Type == MsgTypeSync && m.onMessage != nil {
			m.onMessage(&mMsg)
		}
	}

	// Cleanup peer on disconnect
	m.mu.Lock()
	delete(m.peers, peer.DeviceID)
	m.mu.Unlock()
	conn.Close()
	return nil
}

func (m *Manager) receiveBinaryFile(conn net.Conn, decoder *json.Decoder, name string, size int64) error {
	f, err := os.Create("received_" + name)
	if err != nil {
		return err
	}
	defer f.Close()

	// check if decoder has buffered data
	buffered := decoder.Buffered()
	bufferedBytes, _ := io.ReadAll(buffered)

	bytesToRead := size
	if len(bufferedBytes) > 0 {
		n, _ := f.Write(bufferedBytes)
		bytesToRead -= int64(n)
	}

	if bytesToRead > 0 {
		_, err = io.CopyN(f, conn, bytesToRead)
	}

	m.logger.Info("File saved", "name", name)
	return err
}

func (m *Manager) sendFileAccept(conn net.Conn, fileID string) {
	encoder := json.NewEncoder(conn)
	acceptMsg := &Message{
		Type: "file_accept",
		Payload: &Payload{
			ContentHash: fileID,
		},
	}
	encoder.Encode(acceptMsg)
}

func (m *Manager) SendFile(peerID string, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, _ := file.Stat()

	m.mu.RLock()
	peer, ok := m.peers[peerID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("peer offline")
	}

	// New connection for file transfer
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	dataConn, err := tls.DialWithDialer(dialer, "tcp", peer.Address, m.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to open data channel: %w", err)
	}
	defer dataConn.Close()

	encoder := json.NewEncoder(dataConn)
	msg := &Message{
		Type:     "file_offer",
		DeviceID: m.deviceID,
		Payload: &Payload{
			FileName: filepath.Base(filePath),
			Size:     info.Size(),
		},
	}

	if err := encoder.Encode(msg); err != nil {
		return err
	}

	// wait for acceptance
	decoder := json.NewDecoder(dataConn)
	var resp Message
	if err := decoder.Decode(&resp); err != nil || resp.Type != "file_accept" {
		return fmt.Errorf("transfer rejected")
	}

	_, err = io.Copy(dataConn, file)
	return err
}

func (m *Manager) streamFileData(peer *Peer, file *os.File) error {
	// use io.Copy to stream file data instead of reading into memory
	n, err := io.Copy(peer.Conn, file)
	if err != nil {
		return fmt.Errorf("error during streaming: %w", err)
	}

	m.logger.Info("Transfer finished successfully", "bytes", n)
	return nil
}

func (m *Manager) BroadcastClipBoard(content string) {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))

	// Deduplication
	if hash == m.lastHash {
		return
	}
	m.lastHash = hash

	msg := &Message{
		Type:      MsgTypeSync,
		DeviceID:  m.deviceID,
		Timestamp: time.Now(),
		Payload: &Payload{
			ClipboardContent: content,
			ContentHash:      hash,
		},
	}

	m.mu.RLock()
	peerCount := len(m.peers)
	for _, peer := range m.peers {
		go func(p *Peer) {
			encoder := json.NewEncoder(p.Conn)
			if err := encoder.Encode(msg); err != nil {
				m.logger.Error("Broadcast failed",
					"peer", p.DeviceName,
					"error", err,
				)
			}
		}(peer)
	}
	m.mu.RUnlock()

	if peerCount > 0 {
		m.logger.Debug("Clipboard broadcasted (encrypted)",
			"peer_count", peerCount,
			"size", len(content),
		)
	}
}

func (m *Manager) GetPeers() []PeerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make([]PeerInfo, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, peer.Info())
	}
	return peers
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

func cipherSuiteName(suite uint16) string {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		return "AES-128-GCM"
	case tls.TLS_AES_256_GCM_SHA384:
		return "AES-256-GCM"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "CHACHA20-POLY1305"
	default:
		return fmt.Sprintf("0x%04x", suite)
	}
}
