package p2p

import (
	"bufio"
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

	onFileReceive FileReceiveCallback
}

type FileReceiveCallback func(senderName, fileName string, fileSize int64) (bool, string)

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

// set callback for incoming file offers
func (m *Manager) SetOnFileReceive(callback FileReceiveCallback) {
	m.onFileReceive = callback
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

			go func() {
				err := m.handleConnection(tlsConn, false)
				if err != nil {
					m.logger.Error("Connection handling error", "error", err)
				}
			}()
		}
	}()

	return nil
}

// Connect establishes a TLS connection to a peer
func (m *Manager) Connect(deviceID, address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.peers[deviceID]

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
	reader := bufio.NewReader(conn)
	decoder := json.NewDecoder(reader)
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
				Version:    "1.0.0",
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

	// receive file offer and handle it
	if msg.Type == MsgTypeFileOffer {
		fileName := msg.Payload.FileName
		fileSize := msg.Payload.Size
		senderName := "Unknown"

		m.logger.Info("File offer received", "file", fileName, "size", fileSize)

		// find sender's name from peers list
		m.mu.RLock()
		if peer, exists := m.peers[msg.DeviceID]; exists {
			senderName = peer.DeviceName
		}
		m.mu.RUnlock()

		var accepted bool
		var savePath string

		if m.onFileReceive != nil {
			accepted, savePath = m.onFileReceive(senderName, fileName, fileSize)
		} else {
			m.logger.Warn("No file receive callback set - auto-accepting")
			accepted = true
			var err error
			savePath, err = getDownloadPath(fileName)
			if err != nil {
				m.logger.Error("Failed to get download path", "error", err)
				conn.Close()
				return err
			}
		}

		if !accepted {
			m.logger.Info("File transfer rejected by user", "file", fileName)
			conn.Close()
			return nil
		}

		m.logger.Info("File transfer accepted", "file", fileName, "save_path", savePath)

		if err := m.sendFileAccept(conn, ""); err != nil {
			m.logger.Error("Failed to send acceptance", "error", err)
			conn.Close()
			return err
		}
		return m.receiveBinaryFileToPath(reader, decoder, fileName, fileSize, savePath)
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

func (m *Manager) receiveBinaryFileToPath(reader io.Reader, decoder *json.Decoder, name string, size int64, savePath string) error {
	m.logger.Info("Starting file download", "file", name, "size", size, "path", savePath)

	dir := filepath.Dir(savePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	f, err := os.Create(savePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	// check and skip leading newline if present to prevent corruption of binary files
	var written int64 = 0

	// use bufio.Reader to peek the first byte without consuming it
	var br *bufio.Reader
	if bufReader, ok := reader.(*bufio.Reader); ok {
		br = bufReader
	} else {
		br = bufio.NewReader(reader)
	}

	firstByte, err := br.Peek(1)
	if err != nil && err != io.EOF {
		return fmt.Errorf("peek failed: %w", err)
	}

	// if new line is present, skip it
	if len(firstByte) > 0 && (firstByte[0] == 0x0a || firstByte[0] == 0x0d) {
		br.ReadByte()
		m.logger.Debug("Skipped leading newline")
	}

	written, err = io.CopyN(f, br, size)

	if err != nil {
		return fmt.Errorf("copy failed: %w (got %d/%d)", err, written, size)
	}

	if written != size {
		return fmt.Errorf("size mismatch: %d != %d", written, size)
	}

	f.Sync()
	m.logger.Info("Saved", "bytes", written)
	return nil
}

func (m *Manager) receiveBinaryFile(conn net.Conn, decoder *json.Decoder, name string, size int64) error {
	savePath, err := getDownloadPath(name)
	if err != nil {
		return fmt.Errorf("failed to get download path: %w", err)
	}
	return m.receiveBinaryFileToPath(conn, decoder, name, size, savePath)
}

func getDownloadPath(filename string) (string, error) {
	var downloadDir string

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		downloadDir = filepath.Join(home, "Downloads")
	case "windows":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		downloadDir = filepath.Join(home, "Downloads")
	default: // linux
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		downloadDir = filepath.Join(home, "Downloads")
	}

	// Ensure directory exists
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return "", err
	}

	// Handle duplicate filenames
	savePath := filepath.Join(downloadDir, filename)
	if _, err := os.Stat(savePath); err == nil {
		// File exists, add timestamp
		ext := filepath.Ext(filename)
		base := filename[:len(filename)-len(ext)]
		savePath = filepath.Join(downloadDir, fmt.Sprintf("%s_%d%s", base, time.Now().Unix(), ext))
	}

	return savePath, nil
}

func (m *Manager) sendFileAccept(conn net.Conn, fileID string) error {
	encoder := json.NewEncoder(conn)
	acceptMsg := &Message{
		Type:      MsgTypeFileAccept,
		DeviceID:  m.deviceID,
		Timestamp: time.Now(),
		Payload: &Payload{
			ContentHash: fileID,
		},
	}
	return encoder.Encode(acceptMsg)
}

func (m *Manager) SendFile(peerID string, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

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

	// Send file offer
	encoder := json.NewEncoder(dataConn)
	msg := &Message{
		Type:     MsgTypeFileOffer,
		DeviceID: m.deviceID,
		Payload: &Payload{
			FileName: filepath.Base(filePath),
			Size:     info.Size(),
		},
	}

	if err := encoder.Encode(msg); err != nil {
		return fmt.Errorf("failed to send file offer: %w", err)
	}

	// Wait for acceptance
	decoder := json.NewDecoder(dataConn)
	var resp Message
	if err := decoder.Decode(&resp); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if resp.Type != MsgTypeFileAccept {
		return fmt.Errorf("transfer rejected: %s", resp.Type)
	}

	// Send file data
	written, err := io.Copy(dataConn, file)
	if err != nil {
		return fmt.Errorf("failed to send file data: %w", err)
	}

	m.logger.Info("File sent", "name", filepath.Base(filePath), "size", written)
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
