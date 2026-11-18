package ui

import (
	"os"
	"sync"
)

var (
	vtOnce sync.Once
	vtOK   bool
)

// ansiCapable reports whether stdout can actually render ANSI escapes, enabling Windows
// virtual-terminal processing the first time it is asked.
//
// This is the single gate for both colour and box-drawing glyphs. They were previously
// decided separately — colour by a TTY check, glyphs by an environment-variable guess — so
// a plain Windows console could end up with UTF-8 borders and no colour support, or with
// colour enabled on a console that would print the escape codes literally. One capability
// check keeps the two in step.
func ansiCapable() bool {
	vtOnce.Do(func() {
		if !isTerminal(os.Stdout) {
			vtOK = false
			return
		}
		vtOK = enableVirtualTerminal(os.Stdout)
	})
	return vtOK
}

// AnsiCapable reports whether stdout can render ANSI escapes.
func AnsiCapable() bool {
	return ansiCapable()
}

// IsInteractive reports whether stdout is an interactive terminal capable of
// rich cursor movement, animation, and ANSI styling.
func IsInteractive() bool {
	return isTerminal(os.Stdout) && ansiCapable() && T.On
}
