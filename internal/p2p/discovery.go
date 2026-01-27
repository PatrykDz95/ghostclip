package p2p

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

const (
	ServiceName = "_clipboard._tcp"
)

type Discovery struct {
	deviceID   string
	deviceName string
	port       int
	onPeer     func(deviceID, address string)
}

func NewDiscovery(deviceID, deviceName string, port int, onPeer func(string, string)) *Discovery {
	return &Discovery{
		deviceID:   deviceID,
		deviceName: deviceName,
		port:       port,
		onPeer:     onPeer,
	}
}

// Advertise announces the device on the local network
func (d *Discovery) Advertise(ctx context.Context) error {
	info := []string{
		fmt.Sprintf("device_id=%s", d.deviceID),
		fmt.Sprintf("device_name=%s", d.deviceName),
	}

	service, err := mdns.NewMDNSService(
		d.deviceID,
		ServiceName,
		"",
		"",
		d.port,
		nil,
		info,
	)
	if err != nil {
		return fmt.Errorf("failed to create mDNS service: %w", err)
	}

	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return fmt.Errorf("failed to start mDNS server: %w", err)
	}

	go func() {
		<-ctx.Done()
		server.Shutdown()
	}()

	return nil
}

func (d *Discovery) Discover(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			d.scan()
		}
	}
}

func (d *Discovery) scan() {
	entriesCh := make(chan *mdns.ServiceEntry, 10)

	go func() {
		for entry := range entriesCh {
			// Ignore self
			if strings.Contains(entry.Name, d.deviceID) {
				continue
			}

			deviceID := extractField(entry.InfoFields, "device_id")
			if deviceID == "" {
				continue
			}

			addr := fmt.Sprintf("%s:%d", entry.AddrV4, entry.Port)

			if d.onPeer != nil {
				d.onPeer(deviceID, addr)
			}
		}
	}()

	mdns.Query(&mdns.QueryParam{
		Service: ServiceName,
		Timeout: 3 * time.Second,
		Entries: entriesCh,
	})
}

func extractField(fields []string, key string) string {
	prefix := key + "="
	for _, field := range fields {
		if strings.HasPrefix(field, prefix) {
			return strings.TrimPrefix(field, prefix)
		}
	}
	return ""
}
