// Package ui centralises terminal presentation: glyph sets, the palette, panel and
// gauge primitives, the banner every command prints, and text layout helpers.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Symbols is the glyph vocabulary for the current terminal.
type Symbols struct {
	Unicode bool
	Shield  string
	OK      string
	Fail    string
	Warn    string
	Arrow   string
	Bullet  string
	Dot     string
	Rule    string
}

// ASCII is the always-safe glyph set.
var ASCII = Symbols{
	Shield: "[S]", OK: "OK", Fail: "FAIL", Warn: "!",
	Arrow: "->", Bullet: "-", Dot: ".", Rule: "-",
}

// Unicode is used on terminals known to handle UTF-8 box drawing.
var Unicode = Symbols{
	Unicode: true, Shield: "[S]", OK: "\u2713", Fail: "\u2717",
	Warn: "\u26A0", Arrow: "\u2192", Bullet: "\u2022", Dot: "\u00B7", Rule: "\u2500",
}

// Sym is the glyph set selected for this process.
var Sym = Detect()

// Detect picks a glyph set.
//
// Box drawing (╭─╮) and block glyphs (█) are UTF-8 multibyte characters. They are only
// safe to emit when stdout is a console that has been switched to UTF-8 output and that
// interprets ANSI — which is exactly what ansiCapable() guarantees, and the same gate the
// palette uses. Deciding glyphs by environment variable alone is how the banner once
// rendered as mojibake on a non-UTF8 console.
func Detect() Symbols {
	if v := envLower("SENTINEL_GLYPHS"); v == "ascii" || v == "plain" {
		return ASCII
	}
	if v := envLower("SENTINEL_GLYPHS"); v == "unicode" {
		return Unicode
	}
	if v := envLower("SENTINEL_ASCII"); v == "1" || v == "true" {
		return ASCII
	}
	if v := envLower("SENTINEL_UNICODE"); v == "1" || v == "true" {
		return Unicode
	}
	if ansiCapable() {
		return Unicode
	}
	return ASCII
}

func envLower(key string) string {
	return strings.ToLower(strings.TrimSpace(os.Getenv(key)))
}

func isTerminal(f *os.File) bool {
	if os.Getenv("WT_SESSION") != "" || os.Getenv("TERM_PROGRAM") != "" {
		return true
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

var version = "dev"

// SetVersion records the build version so every banner reports the same one.
func SetVersion(v string) {
	if v != "" {
		version = v
	}
}

// Version returns the version used in banners.
func Version() string { return version }

// RepoURL is printed under the header of every command.
const RepoURL = "https://github.com/DraculaHub786/DevSecOps-Unified-Scanner"

// Headline is the strap line under the wordmark.
const Headline = "DEVSECOPS UNIFIED SCANNER"

// Banner prints the standard header used by every command.
//
// The layout is an instrument panel rather than prose: a block wordmark on the left, a
// column of readouts on the right, a hairline rule closing the block. Every command
// prints this same block, because a tool that greets you differently depending on which
// subcommand you ran looks unfinished.
func Banner(w io.Writer) {
	mark := Wordmark("SENTINEL")
	const markWidth = 47 // "SENTINEL" is 8 glyphs at 5 columns plus 7 separators
	const gutter = 3

	readout := [5]string{
		Fg(T.Dark, "VERSION  ") + Fg(T.Bright, version),
		Fg(T.Dark, "AUTHOR   ") + Fg(T.Bright, "@DraculaHub786"),
		Fg(T.Dark, "MODE     ") + Fg(T.Primary, "LOCAL-FIRST"),
		Fg(T.Dark, "EGRESS   ") + Fg(T.Primary, "NONE"),
		Fg(T.Dark, "LICENSE  ") + Fg(T.Bright, "MIT"),
	}

	fmt.Fprintln(w)
	for i, row := range mark {
		// Top and bottom strokes in the brighter tone give the mark a lit edge.
		colour := T.Primary
		if i == 0 || i == 4 {
			colour = T.Bright
		}
		left := PadRight(Paint(row, colour, T.Bold), markWidth)
		fmt.Fprintf(w, "%s%s%s\n", left, strings.Repeat(" ", gutter), readout[i])
	}

	pw := GetPanelWidth()
	label := " " + Headline + " "
	fill := pw - VisibleWidth(label) - 2
	if fill < 2 {
		fill = 2
	}
	fmt.Fprintf(w, "%s%s%s%s\n",
		Fg(T.Muted, Sym.Rule),
		BoldTxt(T.Muted, label),
		Fg(T.Dark, strings.Repeat(Sym.Rule, fill)),
		Fg(T.Muted, Sym.Rule),
	)
	fmt.Fprintf(w, "%s\n\n", Fg(T.Dark, RepoURL))
}

// SectionHeader prints a labelled rule between blocks, used outside panels.
func SectionHeader(w io.Writer, label string) {
	pw := GetPanelWidth()
	text := Fg(T.Muted, strings.ToUpper(label))
	fill := pw - VisibleWidth(text) - 1
	if fill < 1 {
		fill = 1
	}
	fmt.Fprintf(w, "%s %s\n", text, Fg(T.Dark, strings.Repeat(Sym.Rule, fill)))
}

// Wrap breaks text into lines of at most width runes, preferring word boundaries.
// Truncation was removing the actionable half of finding messages
// ("...AWS credentia..."), which is worse than useless: the reader cannot act on it.
func Wrap(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	var cur strings.Builder
	curLen := 0
	for _, word := range words {
		wl := len([]rune(word))
		if curLen == 0 {
			cur.WriteString(word)
			curLen = wl
			continue
		}
		if curLen+1+wl > width {
			lines = append(lines, cur.String())
			cur.Reset()
			cur.WriteString(word)
			curLen = wl
			continue
		}
		cur.WriteByte(' ')
		cur.WriteString(word)
		curLen += 1 + wl
	}
	if curLen > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

// Trim shortens path-like strings from the left, keeping the filename visible.
func Trim(s string, max int) string {
	r := []rune(s)
	if len(r) <= max || max <= 3 {
		return s
	}
	return "..." + string(r[len(r)-(max-3):])
}

// Truncate shortens descriptive text from the right, appending "..." if it exceeds max runes.
// It also collapses newlines and multiple spaces into a single space so text fits cleanly on one line.
func Truncate(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= max || max <= 3 {
		return s
	}
	return string(r[:max-3]) + "..."
}
