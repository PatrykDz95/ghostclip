package app

import "flag"

const defaultPort = 9876

type Config struct {
	Verbose    bool
	DeviceName string
	Port       int
	PeerAddr   string
}

// parses command-line flags and returns configuration
func parseFlags() *Config {
	cfg := &Config{}

	flag.BoolVar(&cfg.Verbose, "v", false, "verbose logging")
	flag.StringVar(&cfg.DeviceName, "name", "", "device name")
	flag.IntVar(&cfg.Port, "port", defaultPort, "listening port")
	flag.StringVar(&cfg.PeerAddr, "peer", "", "manual peer address")

	flag.Parse()

	return cfg
}
