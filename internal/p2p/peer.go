package p2p

import (
	"net"
	"time"
)

type Peer struct {
	DeviceID   string
	DeviceName string
	OS         string
	Address    string
	Conn       net.Conn
	LastSeen   time.Time
}

type PeerInfo struct {
	DeviceID   string
	DeviceName string
	OS         string
	Address    string
	LastSeen   time.Time
}

func (p *Peer) Info() PeerInfo {
	return PeerInfo{
		DeviceID:   p.DeviceID,
		DeviceName: p.DeviceName,
		OS:         p.OS,
		Address:    p.Address,
		LastSeen:   p.LastSeen,
	}
}
