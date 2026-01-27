//go:build linux

package clipboard

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type linuxClipboard struct {
	lastHash [32]byte
	useXsel  bool
}

func newClipboard() (Clipboard, error) {
	if _, err := exec.LookPath("xclip"); err == nil {
		return &linuxClipboard{useXsel: false}, nil
	}
	if _, err := exec.LookPath("xsel"); err == nil {
		return &linuxClipboard{useXsel: true}, nil
	}
	return nil, fmt.Errorf("xclip or xsel required for clipboard access")
}

func (c *linuxClipboard) Get() (string, error) {
	var cmd *exec.Cmd

	if c.useXsel {
		cmd = exec.Command("xsel", "--clipboard", "--output")
	} else {
		cmd = exec.Command("xclip", "-selection", "clipboard", "-o")
	}

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("clipboard read failed: %w", err)
	}
	return string(out), nil
}

func (c *linuxClipboard) Set(content string) error {
	var cmd *exec.Cmd

	if c.useXsel {
		cmd = exec.Command("xsel", "--clipboard", "--input")
	} else {
		cmd = exec.Command("xclip", "-selection", "clipboard")
	}

	cmd.Stdin = strings.NewReader(content)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clipboard write failed: %w", err)
	}
	return nil
}

func (c *linuxClipboard) Watch(onChange func(content string)) error {
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
