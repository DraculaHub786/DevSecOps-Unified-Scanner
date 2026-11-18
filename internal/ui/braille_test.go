package ui

import (
	"fmt"
	"math"
	"testing"
)

func TestBrailleCanvasBasic(t *testing.T) {
	c := NewBrailleCanvas(34, 11)
	if c.PixelWidth() != 68 || c.PixelHeight() != 44 {
		t.Fatalf("expected 68x44, got %dx%d", c.PixelWidth(), c.PixelHeight())
	}

	cx, cy := 34, 22
	c.DrawCircle(cx, cy, 20)
	c.DrawDashedCircle(cx, cy, 14, 12, 0.5)
	c.DrawDashedCircle(cx, cy, 8, 8, -0.5)
	c.DrawRadarSweep(cx, cy, 20, math.Pi/4, math.Pi/6)
	c.DrawCrosshair(cx, cy, 20, 3)

	lines := c.Render("")
	if len(lines) != 11 {
		t.Fatalf("expected 11 lines, got %d", len(lines))
	}
	for i, l := range lines {
		vw := VisibleWidth(l)
		if vw != 34 {
			t.Errorf("row %d width = %d, expected 34. Line: %q", i, vw, l)
		}
	}
	fmt.Printf("\n--- Rendered Braille Radar ---\n")
	for _, l := range lines {
		fmt.Println(l)
	}
	fmt.Printf("------------------------------\n")
}
