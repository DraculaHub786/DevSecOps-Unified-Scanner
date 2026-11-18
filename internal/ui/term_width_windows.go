//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

func getSystemTerminalWidth() int {
	var csbi windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(os.Stdout.Fd()), &csbi); err == nil {
		w := int(csbi.Window.Right - csbi.Window.Left + 1)
		if w >= 40 {
			return w
		}
	}
	return 80
}
