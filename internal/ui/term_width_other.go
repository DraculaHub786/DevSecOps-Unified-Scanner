//go:build !windows

package ui

import (
	"os"
	"strconv"
)

func getSystemTerminalWidth() int {
	if colStr := os.Getenv("COLUMNS"); colStr != "" {
		if c, err := strconv.Atoi(colStr); err == nil && c >= 40 {
			return c
		}
	}
	return 80
}
