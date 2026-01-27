//go:build windows

package clipboard

import (
	"crypto/sha256"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	openClipboard    = user32.NewProc("OpenClipboard")
	closeClipboard   = user32.NewProc("CloseClipboard")
	getClipboardData = user32.NewProc("GetClipboardData")
	setClipboardData = user32.NewProc("SetClipboardData")
	emptyClipboard   = user32.NewProc("EmptyClipboard")
)

const (
	cfUnicodeText = 13
)

type windowsClipboard struct {
	lastHash [32]byte
}

func newClipboard() (Clipboard, error) {
	return &windowsClipboard{}, nil
}

func (c *windowsClipboard) Get() (string, error) {
	r, _, err := openClipboard.Call(0)
	if r == 0 {
		return "", fmt.Errorf("failed to open clipboard: %w", err)
	}
	defer closeClipboard.Call()

	h, _, _ := getClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil
	}

	ptr := windows.GlobalLock(windows.Handle(h))
	if ptr == nil {
		return "", fmt.Errorf("failed to lock clipboard memory")
	}
	defer windows.GlobalUnlock(windows.Handle(h))

	return windows.UTF16PtrToString((*uint16)(ptr)), nil
}

func (c *windowsClipboard) Set(content string) error {
	r, _, err := openClipboard.Call(0)
	if r == 0 {
		return fmt.Errorf("failed to open clipboard: %w", err)
	}
	defer closeClipboard.Call()

	emptyClipboard.Call()

	utf16, err := syscall.UTF16FromString(content)
	if err != nil {
		return fmt.Errorf("failed to convert to UTF16: %w", err)
	}

	h := windows.GlobalAlloc(windows.GMEM_MOVEABLE, uintptr(len(utf16)*2))
	if h == 0 {
		return fmt.Errorf("failed to allocate global memory")
	}

	ptr := windows.GlobalLock(h)
	if ptr == nil {
		windows.GlobalFree(h)
		return fmt.Errorf("failed to lock global memory")
	}

	dstSlice := unsafe.Slice((*uint16)(ptr), len(utf16))
	copy(dstSlice, utf16)

	windows.GlobalUnlock(h)

	r, _, err = setClipboardData.Call(cfUnicodeText, uintptr(h))
	if r == 0 {
		return fmt.Errorf("failed to set clipboard data: %w", err)
	}

	return nil
}

func (c *windowsClipboard) Watch(onChange func(content string)) error {
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
