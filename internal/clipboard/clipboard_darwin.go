//go:build darwin

package clipboard

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type darwinClipboard struct {
	lastHash [32]byte
}

func newClipboard() (Clipboard, error) {
	if _, err := exec.LookPath("pbpaste"); err != nil {
		return nil, fmt.Errorf("pbpaste not found: %w", err)
	}
	if _, err := exec.LookPath("pbcopy"); err != nil {
		return nil, fmt.Errorf("pbcopy not found: %w", err)
	}

	return &darwinClipboard{}, nil
}

func (c *darwinClipboard) Get() (string, error) {
	cmd := exec.Command("pbpaste")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("pbpaste failed: %w", err)
	}
	return string(out), nil
}

func (c *darwinClipboard) Set(content string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(content)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pbcopy failed: %w", err)
	}
	return nil
}

func (c *darwinClipboard) Watch(onChange func(content string)) error {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		content, err := c.Get()
		if err != nil {
			continue
		}

		if content == "" {
			continue
		}

		hash := sha256.Sum256([]byte(content))
		if hash != c.lastHash {
			c.lastHash = hash
			onChange(content)
		}
	}

	return nil
}
