//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal prepares the Windows console for the HUD interface.
//
// Two separate things have to be true before the design renders correctly, and missing
// either produces output that looks broken in a different way:
//
//   - ENABLE_VIRTUAL_TERMINAL_PROCESSING makes the console interpret ANSI escapes.
//     Without it the user sees raw `?[38;5;42m` written into their terminal — the
//     "colour" becomes garbage text, which is worse than no colour at all.
//   - The output codepage must be UTF-8. Box drawing (╭─╮) and block glyphs (█) are
//     multibyte; on the legacy 437 or 1252 codepage they render as `ΓöÇ` mojibake, the
//     exact failure this project already hit once with emoji in the banner.
//
// Returns false when stdout is not a console (piped or redirected) or either call fails,
// and the caller treats that as "plain text, ASCII glyphs".
func enableVirtualTerminal(f *os.File) bool {
	handle := windows.Handle(f.Fd())

	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
		if err := windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
			return false
		}
	}

	// SetConsoleOutputCP is process-wide and idempotent; failure here is not fatal,
	// because a console that already speaks UTF-8 returns an error that means nothing.
	_ = windows.SetConsoleOutputCP(65001 /* CP_UTF8 */)

	return true
}
