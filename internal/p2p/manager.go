package p2p

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
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
		var msg Message
		if err := decoder.Decode(&msg); err != nil {
			break
		}

		peer.LastSeen = time.Now()

		if m.onMessage != nil {
			m.onMessage(&msg)
		}
	}

	// Cleanup
	m.mu.Lock()
	delete(m.peers, peer.DeviceID)
	m.mu.Unlock()
	conn.Close()

	m.logger.Info("Peer disconnected", "device_name", peer.DeviceName)
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
