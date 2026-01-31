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
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	openClipboard    = user32.NewProc("OpenClipboard")
	closeClipboard   = user32.NewProc("CloseClipboard")
	getClipboardData = user32.NewProc("GetClipboardData")
	setClipboardData = user32.NewProc("SetClipboardData")
	emptyClipboard   = user32.NewProc("EmptyClipboard")

	globalAlloc  = kernel32.NewProc("GlobalAlloc")
	globalFree   = kernel32.NewProc("GlobalFree")
	globalLock   = kernel32.NewProc("GlobalLock")
	globalUnlock = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002 // value GMEM_MOVEABLE
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

	ptr, _, _ := globalLock.Call(h)
	if ptr == 0 {
		return "", fmt.Errorf("failed to lock clipboard memory")
	}
	defer globalUnlock.Call(h)

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr))), nil
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

	h, _, _ := globalAlloc.Call(gmemMoveable, uintptr(len(utf16)*2))
	if h == 0 {
		return fmt.Errorf("failed to allocate global memory")
	}

	ptr, _, _ := globalLock.Call(h)
	if ptr == 0 {
		globalFree.Call(h)
		return fmt.Errorf("failed to lock global memory")
	}

	dstSlice := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(utf16))
	copy(dstSlice, utf16)

	globalUnlock.Call(h)

	r, _, err = setClipboardData.Call(cfUnicodeText, h)
	if r == 0 {
		return fmt.Errorf("failed to set clipboard data: %w", err)
	}
	c.lastHash = sha256.Sum256([]byte(content)) // prevent feedback loop
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
