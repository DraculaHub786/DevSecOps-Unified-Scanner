package ui

// Every non-ASCII glyph in the interface has to go through a helper like these.
//
// Hardcoding them is what produced "┬╖" and "ΓùÅ" in the output: the box drawing and the
// wordmark correctly degraded to ASCII because the glyph set was plain, but a "·" and a
// "●" written directly into a format string stayed UTF-8 and were printed to a console
// using a different codepage. Mixed glyph sets are the whole failure mode this package
// exists to prevent, so nothing may bypass it.

// MarkOn is the filled status dot.
func MarkOn() string {
	if Sym.Unicode {
		return "●"
	}
	return "*"
}

// MarkOff is the hollow status dot.
func MarkOff() string {
	if Sym.Unicode {
		return "○"
	}
	return "o"
}

// MarkHalf is the partial status dot, used for degraded engines.
func MarkHalf() string {
	if Sym.Unicode {
		return "◐"
	}
	return "~"
}

// DashGlyph is the horizontal filler used between blocks inside a finding list.
func DashGlyph() string {
	if Sym.Unicode {
		return "┈"
	}
	return "-"
}

// ArrowGlyph is the outdent used for remediation hints.
func ArrowGlyph() string { return Sym.Arrow }
