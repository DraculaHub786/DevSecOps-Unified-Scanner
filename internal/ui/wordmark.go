package ui

import "strings"

// letterFont is a 5-row, 5-column block alphabet. Only the letters needed for the
// wordmark are defined; anything else falls back to blank so a typo cannot panic.
var letterFont = map[rune][]string{
	'S': {"█████", "█    ", "████ ", "    █", "█████"},
	'E': {"█████", "█    ", "████ ", "█    ", "█████"},
	'N': {"█   █", "██  █", "█ █ █", "█  ██", "█   █"},
	'T': {"█████", "  █  ", "  █  ", "  █  ", "  █  "},
	'I': {"█████", "  █  ", "  █  ", "  █  ", "█████"},
	'L': {"█    ", "█    ", "█    ", "█    ", "█████"},
	'A': {" ███ ", "█   █", "█████", "█   █", "█   █"},
	'F': {"█████", "█    ", "████ ", "█    ", "█    "},
	'J': {"█████", "   █ ", "   █ ", "█  █ ", " ██  "},
	'V': {"█   █", "█   █", "█   █", " █ █ ", "  █  "},
	'C': {"█████", "█    ", "█    ", "█    ", "█████"},
	'D': {"████ ", "█   █", "█   █", "█   █", "████ "},
	'H': {"█   █", "█   █", "█████", "█   █", "█   █"},
	'R': {"████ ", "█   █", "████ ", "█  █ ", "█   █"},
	'U': {"█   █", "█   █", "█   █", "█   █", "█████"},
	'Y': {"█   █", " █ █ ", "  █  ", "  █  ", "  █  "},
	' ': {"     ", "     ", "     ", "     ", "     "},
}

// Wordmark renders text as block letters across five rows, one space between glyphs.
//
// The glyph degrades to "#" on an ASCII console. Without this the wordmark stayed
// Unicode while the panels around it degraded to "+---", so a single screen looked like
// two programs rendering it — the same mixed-glyph failure that made the original banner
// unreadable on cmd.exe.
func Wordmark(text string) []string {
	const height = 5
	block := BlockGlyph()
	rows := make([]string, height)
	for i, ch := range strings.ToUpper(text) {
		glyph, ok := letterFont[ch]
		if !ok {
			glyph = letterFont[' ']
		}
		for row := 0; row < height; row++ {
			if i > 0 {
				rows[row] += " "
			}
			rows[row] += strings.ReplaceAll(glyph[row], "█", block)
		}
	}
	return rows
}

// WordmarkWidth reports the printed width of a wordmark, used for centring.
func WordmarkWidth(text string) int {
	if text == "" {
		return 0
	}
	return len([]rune(text))*6 - 1
}
