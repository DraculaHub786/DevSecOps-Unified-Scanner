package ui

import (
	"os"
	"strings"
)

// Theme holds the ANSI sequences for the phosphor-HUD look: a dark canvas with bright
// green primary text, dim green chrome, and saturated accents for severity.
//
// Every field is empty when colour is disabled, so callers never need to branch. That
// matters because the same render path serves an interactive terminal and a redirected
// file, and the file must not contain escape codes.
type Theme struct {
	On bool

	Reset     string
	Bold      string
	Dim       string
	Italic    string
	Underline string
	Inverse   string

	// Palette
	Primary     string // phosphor green, the dominant colour
	Bright      string // near-white green for emphasis
	Neon        string // ultra-bright electric matrix green (#00FF66)
	Muted       string // dim green for chrome, borders, secondary labels
	Dark        string // very dim green for rules and fills
	Cyan        string
	CyanBright  string // electric cyan (#00E5FF)
	Amber       string
	AmberBright string
	Red         string
	RedBright   string
	Magenta     string
	BgDark      string
}

// NoColor is the theme used when output is piped or NO_COLOR is set: identical layout,
// zero escape sequences.
var NoColor = Theme{}

// Phosphor is the default visual language.
var Phosphor = Theme{
	On:          true,
	Reset:       "\033[0m",
	Bold:        "\033[1m",
	Dim:         "\033[2m",
	Italic:      "\033[3m",
	Underline:   "\033[4m",
	Inverse:     "\033[7m",
	Primary:     "\033[38;5;42m",  // bright phosphor green
	Bright:      "\033[38;5;120m", // pale green-white
	Neon:        "\033[38;5;48m",  // electric neon matrix green
	Muted:       "\033[38;5;35m",  // mid green
	Dark:        "\033[38;5;22m",  // deep green
	Cyan:        "\033[38;5;44m",
	CyanBright:  "\033[38;5;51m",  // electric cyan
	Amber:       "\033[38;5;214m",
	AmberBright: "\033[38;5;220m",
	Red:         "\033[38;5;203m",
	RedBright:   "\033[38;5;196m",
	Magenta:     "\033[38;5;171m",
	BgDark:      "\033[48;5;233m",
}

// T is the theme selected for this process.
var T = selectTheme()

// selectTheme decides colour, using the same capability gate as glyph selection.
func selectTheme() Theme {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("SENTINEL_COLOR")))

	// NO_COLOR is the agreed opt-out and is never overridden, including by a force
	// request.
	if os.Getenv("NO_COLOR") != "" || os.Getenv("SENTINEL_NO_COLOR") != "" {
		return NoColor
	}
	if mode == "never" || mode == "0" || mode == "false" {
		return NoColor
	}
	if mode == "always" || mode == "force" || mode == "1" {
		return Phosphor
	}
	// Default: colour whenever the console can render it. On Windows this enables
	// virtual-terminal processing; without that, ANSI escapes print literally and the
	// output is worse than plain text.
	if ansiCapable() {
		return Phosphor
	}
	return NoColor
}

// DisableColors forces the plain theme. Callers that own a --no-color flag use it.
func DisableColors() { T = NoColor }

// ForceColor re-enables the phosphor palette regardless of detection.
func ForceColor() {
	if os.Getenv("NO_COLOR") == "" {
		T = Phosphor
	}
}

// Paint wraps s in the given sequences and always resets, so a nested reset cannot leak
// colour into following text.
func Paint(s string, styles ...string) string {
	if !T.On || len(styles) == 0 {
		return s
	}
	var b strings.Builder
	for _, st := range styles {
		b.WriteString(st)
	}
	b.WriteString(s)
	b.WriteString(T.Reset)
	return b.String()
}

// Fg colourises s with one palette entry.
func Fg(colour, s string) string { return Paint(s, colour) }

// BoldTxt colourises and bolds.
func BoldTxt(colour, s string) string { return Paint(s, colour, T.Bold) }

// VisibleWidth counts runes, ignoring ANSI escapes and zero-width variation selectors,
// so padding and box drawing line up even when the content is coloured.
func VisibleWidth(s string) int {
	width := 0
	inEscape := false
	for _, r := range s {
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '~' || r == '@' {
				inEscape = false
			}
			continue
		}
		if r == '\033' {
			inEscape = true
			continue
		}
		// Zero-width characters (variation selectors, zero-width joiners)
		if r == 0xFE0F || r == 0xFE0E || r == 0x200D || r == 0x200B {
			continue
		}
		width++
	}
	return width
}

// TruncateVisible shortens s to at most maxWidth visible runes while preserving
// ANSI escape codes and closing styles with Reset.
func TruncateVisible(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	var b strings.Builder
	curWidth := 0
	inEscape := false
	for _, r := range s {
		if inEscape {
			b.WriteRune(r)
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '~' || r == '@' {
				inEscape = false
			}
			continue
		}
		if r == '\033' {
			inEscape = true
			b.WriteRune(r)
			continue
		}
		if r == 0xFE0F || r == 0xFE0E || r == 0x200D || r == 0x200B {
			b.WriteRune(r)
			continue
		}
		if curWidth >= maxWidth {
			break
		}
		b.WriteRune(r)
		curWidth++
	}
	if T.On {
		b.WriteString(T.Reset)
	}
	return b.String()
}

// FitToWidth guarantees s occupies EXACTLY width visible columns: padded with spaces
// if shorter, cleanly truncated if longer. This prevents box borders from ever breaking.
func FitToWidth(s string, width int) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	vw := VisibleWidth(s)
	if vw < width {
		return s + strings.Repeat(" ", width-vw)
	}
	if vw > width {
		return TruncateVisible(s, width)
	}
	return s
}

// PadRight pads s with spaces to width visible runes, truncating if it exceeds width.
func PadRight(s string, width int) string {
	return FitToWidth(s, width)
}

// PadLeft left-pads s to width visible runes.
func PadLeft(s string, width int) string {
	pad := width - VisibleWidth(s)
	if pad <= 0 {
		return s
	}
	return strings.Repeat(" ", pad) + s
}

// Center centres s within width visible runes.
func Center(s string, width int) string {
	pad := width - VisibleWidth(s)
	if pad <= 0 {
		return s
	}
	left := pad / 2
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", pad-left)
}
