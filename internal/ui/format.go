package ui

import "strconv"

// Itoa formats an integer, so call sites that only need a decimal string do not have to
// import fmt purely for that.
func Itoa(n int) string { return strconv.Itoa(n) }
