package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// PanelWidth is the default content width, maintained for backwards compatibility.
// Use GetPanelWidth() to obtain the dynamic width calculated from terminal size.
var PanelWidth = 76

// GetPanelWidth calculates the optimal panel content width dynamically
// based on the active terminal window size, clamped safely between 74 and 96 columns.
func GetPanelWidth() int {
	w := getSystemTerminalWidth()
	pw := w - 4
	if pw < 74 {
		pw = 74
	}
	if pw > 96 {
		pw = 96
	}
	return pw
}

// Box is the corner-and-line vocabulary for a panel border.
type Box struct {
	TL, TR, BL, BR string
	H, V           string
}

// Rounded is the default border style.
var Rounded = Box{TL: "╭", TR: "╮", BL: "╰", BR: "╯", H: "─", V: "│"}

// Square is used for emphasis panels.
var Square = Box{TL: "┌", TR: "┐", BL: "└", BR: "┘", H: "─", V: "│"}

// Plain is the ASCII fallback for consoles that cannot render UTF-8 box drawing.
var Plain = Box{TL: "+", TR: "+", BL: "+", BR: "+", H: "-", V: "|"}

// BoxFor returns the border style safe for the current terminal.
func BoxFor() Box {
	if Sym.Unicode || ansiCapable() || os.Getenv("WT_SESSION") != "" || os.Getenv("TERM_PROGRAM") != "" || os.Getenv("TERM") != "" {
		return Rounded
	}
	return Plain
}

// Separator is the mid-dot used between labels, degraded to a hyphen on ASCII consoles
// so a label never renders as mojibake.
func Separator() string {
	if Sym.Unicode {
		return "·"
	}
	return "-"
}

// BlockGlyph returns the solid fill cell used by bars and the wordmark.
func BlockGlyph() string {
	if Sym.Unicode {
		return "█"
	}
	return "#"
}

// Panel writes a titled box. The label sits immediately after the top-left corner and
// the rest of that line is ruled, which is how btop and similar dashboards mark a panel.
// Centring the title (the first attempt) put it a third of the way along and read as a
// misalignment rather than as a deliberate header.
func Panel(w io.Writer, b Box, title string, lines []string) {
	pw := GetPanelWidth()
	PanelWidth = pw
	inner := pw - 2 // one space of padding each side

	label := " " + strings.ToUpper(title) + " "
	label = strings.ReplaceAll(label, "·", Separator())

	// Top line: b.TL (1) + b.H (1) + label (len) + fill + b.TR (1) = inner + 2
	// Therefore fill must be inner - VisibleWidth(label) - 1.
	fill := inner - VisibleWidth(label) - 1
	if fill < 1 {
		fill = 1
	}

	fmt.Fprintf(w, "%s%s%s%s%s\n",
		Fg(T.Muted, b.TL),
		Fg(T.Dark, b.H),
		BoldTxt(T.Primary, label),
		Fg(T.Dark, strings.Repeat(b.H, fill)),
		Fg(T.Muted, b.TR),
	)

	for _, rawLine := range lines {
		clean := strings.ReplaceAll(rawLine, "\r\n", "\n")
		clean = strings.ReplaceAll(clean, "\r", "\n")
		for _, line := range strings.Split(clean, "\n") {
			fmt.Fprintf(w, "%s %s %s\n",
				Fg(T.Muted, b.V),
				FitToWidth(line, inner-2),
				Fg(T.Muted, b.V),
			)
		}
	}

	fmt.Fprintf(w, "%s%s%s\n",
		Fg(T.Muted, b.BL),
		Fg(T.Dark, strings.Repeat(b.H, inner)),
		Fg(T.Muted, b.BR),
	)
}

// SegBar renders a segmented progress bar. The filled portion uses solid blocks and the
// remainder uses shaded ones, so the bar still reads in a monochrome terminal where a
// colour-only distinction would be lost.
func SegBar(frac float64, width int, fillColour string) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	filled := int(float64(width)*frac + 0.5)
	if filled > width {
		filled = width
	}
	on, off := "█", "░"
	if !Sym.Unicode {
		on, off = "#", "."
	}
	return Fg(fillColour, strings.Repeat(on, filled)) +
		Fg(T.Dark, strings.Repeat(off, width-filled))
}

// Segment is one slice of a Distribution bar.
type Segment struct {
	Label  string
	Count  int
	Colour string
}

// Distribution renders a stacked bar showing the composition of findings by severity.
// This replaces a line of coloured counts: the bar communicates proportion at a glance,
// which is what a reader wants before they want exact numbers.
func Distribution(segments []Segment, width int) string {
	total := 0
	for _, s := range segments {
		total += s.Count
	}
	empty, block := "░", "█"
	if !Sym.Unicode {
		empty, block = ".", "#"
	}
	if total == 0 {
		return Fg(T.Dark, strings.Repeat(empty, width))
	}

	last := -1
	for i, s := range segments {
		if s.Count > 0 {
			last = i
		}
	}

	var b strings.Builder
	used := 0
	for i, s := range segments {
		if s.Count == 0 {
			continue
		}
		cell := int(float64(width)*float64(s.Count)/float64(total) + 0.5)
		// The last non-empty segment absorbs rounding error so the bar is exactly
		// `width` cells and the panel border never shifts.
		if i == last {
			cell = width - used
		}
		if cell < 1 {
			cell = 1
		}
		if used+cell > width {
			cell = width - used
		}
		if cell <= 0 {
			continue
		}
		b.WriteString(Fg(s.Colour, strings.Repeat(block, cell)))
		used += cell
	}
	if rem := width - used; rem > 0 {
		b.WriteString(Fg(T.Dark, strings.Repeat(empty, rem)))
	}
	return b.String()
}

// BigDigits renders a number as large LCD-style blocks, used for the headline count.
// A terminal cannot draw the circular dial from the reference art, so the dial becomes an
// oversized numeral over a proportional bar. That still reads as an instrument panel.
func BigDigits(s string) []string {
	const height = 5
	out := make([]string, height)
	first := true
	for _, ch := range s {
		glyph, ok := digitFont[ch]
		if !ok {
			glyph = digitFont[' ']
		}
		for row := 0; row < height; row++ {
			// One blank column between glyphs. Without it two digits merged into a
			// single unreadable mass, because each glyph is exactly three columns.
			if !first {
				out[row] += " "
			}
			out[row] += glyph[row]
		}
		first = false
	}
	if !Sym.Unicode {
		for i := range out {
			out[i] = strings.ReplaceAll(out[i], "█", "#")
		}
	}
	return out
}

// digitFont is a 5-row, 3-column glyph set. Block characters render identically on every
// terminal that supports them, which is why the reference HUDs lean on them too.
var digitFont = map[rune][]string{
	'0': {"███", "█ █", "█ █", "█ █", "███"},
	'1': {"  █", "  █", "  █", "  █", "  █"},
	'2': {"███", "  █", "███", "█  ", "███"},
	'3': {"███", "  █", "███", "  █", "███"},
	'4': {"█ █", "█ █", "███", "  █", "  █"},
	'5': {"███", "█  ", "███", "  █", "███"},
	'6': {"███", "█  ", "███", "█ █", "███"},
	'7': {"███", "  █", "  █", "  █", "  █"},
	'8': {"███", "█ █", "███", "█ █", "███"},
	'9': {"███", "█ █", "███", "  █", "███"},
	' ': {"   ", "   ", "   ", "   ", "   "},
	'-': {"   ", "   ", "███", "   ", "   "},
	'/': {"  █", "  █", "███", "█  ", "█  "},
	'%': {"█ █", "  █", "███", "█  ", "█ █"},
}

// Tag renders a severity chip with reverse video so it stays legible at a glance and
// keeps its meaning when pasted into an issue without colour.
func Tag(label, colour string) string {
	if !T.On {
		return "[" + label + "]"
	}
	return "\033[7m" + colour + T.Bold + " " + label + " " + T.Reset
}

// Sparkline renders a compact trend line, so a reader can tell whether a run was a spike
// or a steady burn — something a single total cannot convey.
func Sparkline(values []float64, width int) string {
	if width <= 0 || len(values) == 0 {
		return ""
	}
	blocks := []rune("▁▂▃▄▅▆▇█")
	if !Sym.Unicode {
		blocks = []rune(".:-=+*#@")
	}

	lo, hi := values[0], values[0]
	for _, v := range values {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	span := hi - lo
	if span <= 0 {
		span = 1
	}

	sampled := make([]float64, 0, width)
	for i := 0; i < width; i++ {
		idx := i * len(values) / width
		if idx >= len(values) {
			idx = len(values) - 1
		}
		sampled = append(sampled, values[idx])
	}

	var b strings.Builder
	for _, v := range sampled {
		pos := int((v - lo) / span * float64(len(blocks)-1))
		if pos < 0 {
			pos = 0
		}
		if pos >= len(blocks) {
			pos = len(blocks) - 1
		}
		b.WriteRune(blocks[pos])
	}
	return Fg(T.Primary, b.String())
}

// KeyValue renders an aligned label/value row: dim label, bright value.
func KeyValue(label, value string, labelWidth int) string {
	return Fg(T.Muted, PadRight(label, labelWidth)) + Fg(T.Bright, value)
}

// StatusMark returns a glyph plus colour for a boolean state.
func StatusMark(ok bool) string {
	if ok {
		return Fg(T.Primary, Sym.OK)
	}
	return Fg(T.Red, Sym.Fail)
}
