//go:build !windows

package ui

import "os"

// enableVirtualTerminal is a no-op off Windows: POSIX terminals interpret ANSI escapes
// natively, so there is nothing to negotiate.
func enableVirtualTerminal(f *os.File) bool { return true }
