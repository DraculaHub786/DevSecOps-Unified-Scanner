package ui

import (
	"fmt"
	"math"
)

// outerAzimuths contains 8 discrete perimeter bearings for the outer clockwise circle.
var outerAzimuths = []string{
	"000° N", "045°NE", "090° E", "135°SE",
	"180° S", "225°SW", "270° W", "315°NW",
}

// RenderRadarFrame renders a high-resolution concentric circular HUD scanner with multiple circles
// rotating in opposite directions (Outer: Clockwise, Middle: Counter-Clockwise,
// Inner: Clockwise, Reticle: Sweeping Ray), matching image copy.png using sub-pixel Braille rasterization.
func RenderRadarFrame(step int, blipCount int, lockedTarget string) []string {
	const radarW = 34
	const canvasRows = 9
	const canvasCols = 34

	// 1. Calculate active rotating azimuth headings
	outerIdx := (step%len(outerAzimuths) + len(outerAzimuths)) % len(outerAzimuths)
	activeAzimuth := outerAzimuths[outerIdx]

	topAzimuth := "000° N"
	bottomAzimuth := "180° S"
	if outerIdx == 0 {
		topAzimuth = Paint(activeAzimuth, T.Neon, T.Bold)
	} else if outerIdx == 4 {
		bottomAzimuth = Paint(activeAzimuth, T.Neon, T.Bold)
	} else {
		topAzimuth = Fg(T.Cyan, activeAzimuth)
		bottomAzimuth = Fg(T.Dark, bottomAzimuth)
	}

	// 2. High-resolution Braille canvas (68 x 36 sub-pixels)
	canvas := NewBrailleCanvas(canvasCols, canvasRows)
	cx := canvas.PixelWidth() / 2  // 34
	cy := canvas.PixelHeight() / 2 // 18

	// Circle 1 (Outer Ring, R=17 sub-pixels): Clockwise tracking cursor
	canvas.DrawCircle(cx, cy, 17)
	// Outer tracking cursor rotating clockwise
	cursorAngle := float64(step) * (2.0 * math.Pi / 24.0)
	curX := int(float64(cx) + 17.0*math.Cos(cursorAngle) + 0.5)
	curY := int(float64(cy) + 17.0*math.Sin(cursorAngle) + 0.5)
	canvas.Set(curX, curY)
	canvas.Set(curX+1, curY)
	canvas.Set(curX, curY+1)

	// Circle 2 (Middle-Outer Ring, R=12 sub-pixels): Counter-Clockwise (Anticlockwise) segmented gear
	ccwPhase := float64(step) * 0.16
	canvas.DrawDashedCircle(cx, cy, 12, 10, +ccwPhase)

	// Circle 3 (Middle-Inner Ring, R=7 sub-pixels): Clockwise segmented ring
	cwPhase := float64(step) * 0.22
	canvas.DrawDashedCircle(cx, cy, 7, 6, -cwPhase)

	// Circle 4 (Central Reticle, R=2 sub-pixels & Crosshairs)
	canvas.DrawCircle(cx, cy, 2)
	canvas.DrawCrosshair(cx, cy, 17, 3)

	// Rotating radar sweep beam & phosphor wake sector (Rotates 360 degrees)
	sweepAngle := float64(step) * (2.0 * math.Pi / 16.0)
	canvas.DrawRadarSweep(cx, cy, 17, sweepAngle, math.Pi/5.0)

	// Active threat blips on radar grid
	type blipInfo struct {
		r     int
		theta float64
		color string
	}
	blips := []blipInfo{
		{11, 0.85, T.Red},
		{15, 2.25, T.Amber},
		{8, 3.75, T.Cyan},
		{13, 5.15, T.Primary},
	}
	activeCount := 0
	if blipCount > 0 {
		activeCount = 1
	}
	if blipCount > 5 {
		activeCount = 2
	}
	if blipCount > 15 {
		activeCount = 3
	}
	if blipCount > 25 {
		activeCount = 4
	}

	for i := 0; i < activeCount && i < len(blips); i++ {
		b := blips[i]
		bx := int(float64(cx) + float64(b.r)*math.Cos(b.theta) + 0.5)
		by := int(float64(cy) + float64(b.r)*math.Sin(b.theta) + 0.5)
		canvas.Set(bx, by)
		canvas.Set(bx+1, by)
		canvas.Set(bx, by+1)
		canvas.SetColor(bx, by, b.color)

		// When radar sweep beam passes over a blip, render expanding ping ring
		diff := math.Abs(math.Remainder(sweepAngle-b.theta, 2.0*math.Pi))
		if diff < 0.35 {
			canvas.DrawCircle(bx, by, 3)
		}
	}

	canvasLines := canvas.Render(T.Neon)

	// Embed equator degree markers into the central row (row 4 of the 9 canvas rows)
	// Preserve the central 22 columns of the radar canvas, flanked by 270° (6 cols) and 090° (6 cols)
	leftPart := Fg(T.Cyan, "270°◄ ")
	rightPart := Fg(T.Cyan, " ►090°")
	centerSlice := canvas.RenderRowRange(4, 6, 28, T.Neon)
	canvasLines[4] = leftPart + centerSlice + rightPart

	// Frame top and bottom bearing rows
	r0 := fmt.Sprintf("     %s %s %s     ", Fg(T.Dark, "╭─────-·"), topAzimuth, Fg(T.Dark, "·-─────╮"))
	r10 := fmt.Sprintf("     %s %s %s     ", Fg(T.Dark, "╰─────-·"), bottomAzimuth, Fg(T.Dark, "·-─────╯"))

	lockStatus := Paint("[ LOCK: ACTIVE ]", T.Neon, T.Bold)
	if blipCount == 0 {
		lockStatus = Fg(T.Dark, "[ SCAN: IDLE   ]")
	}
	threatLabel := Paint(fmt.Sprintf("%d THREATS", blipCount), T.Bright)

	r11 := Center(fmt.Sprintf("%s   %s", lockStatus, threatLabel), radarW)
	r12 := Center(fmt.Sprintf("%s  %s  %s", Fg(T.Neon, "CW:OUT⟳"), Fg(T.Cyan, "CCW:MID⟲"), Fg(T.Neon, "CW:INN⟳")), radarW)

	raw := make([]string, 0, 13)
	raw = append(raw, r0)
	raw = append(raw, canvasLines...)
	raw = append(raw, r10, r11, r12)

	out := make([]string, len(raw))
	for i, line := range raw {
		out[i] = FitToWidth(line, radarW)
	}
	return out
}

// RenderStaticRadar renders a stationary cybersecurity concentric reticle for the report overview.
func RenderStaticRadar(blipCount int, threatLevel string) []string {
	const radarW = 34
	const canvasRows = 9
	const canvasCols = 34

	canvas := NewBrailleCanvas(canvasCols, canvasRows)
	cx := canvas.PixelWidth() / 2  // 34
	cy := canvas.PixelHeight() / 2 // 18

	// Static converged rings
	canvas.DrawCircle(cx, cy, 17)
	canvas.DrawDashedCircle(cx, cy, 12, 10, 0.0)
	canvas.DrawDashedCircle(cx, cy, 7, 6, 0.0)
	canvas.DrawCircle(cx, cy, 2)
	canvas.DrawCrosshair(cx, cy, 17, 3)

	// Static target blips
	if blipCount > 0 {
		bx1 := int(float64(cx) + 11.0*math.Cos(0.85) + 0.5)
		by1 := int(float64(cy) + 11.0*math.Sin(0.85) + 0.5)
		canvas.Set(bx1, by1)
		canvas.Set(bx1+1, by1)
		canvas.SetColor(bx1, by1, T.Red)

		bx2 := int(float64(cx) + 15.0*math.Cos(2.25) + 0.5)
		by2 := int(float64(cy) + 15.0*math.Sin(2.25) + 0.5)
		canvas.Set(bx2, by2)
		canvas.Set(bx2+1, by2)
		canvas.SetColor(bx2, by2, T.Amber)
	}

	canvasLines := canvas.Render(T.Neon)

	// Embed equator degree markers into central row
	leftPart := Fg(T.Cyan, "270°◄ ")
	rightPart := Fg(T.Cyan, " ►090°")
	centerSlice := canvas.RenderRowRange(4, 6, 28, T.Neon)
	canvasLines[4] = leftPart + centerSlice + rightPart

	r0 := fmt.Sprintf("   %s %s %s   ", Fg(T.Dark, "╭────-·"), Fg(T.Neon, "RADAR LOCK"), Fg(T.Dark, "·-────╮"))
	r10 := fmt.Sprintf("   %s %s %s   ", Fg(T.Dark, "╰────-·"), Fg(T.Cyan, "AZIMUTH 360°"), Fg(T.Dark, "·-────╯"))

	r11 := Center(fmt.Sprintf("%s %s", Fg(T.Dark, "SURFACE:"), Fg(T.Bright, fmt.Sprintf("%d DETECTIONS", blipCount))), radarW)
	r12 := Center(fmt.Sprintf("%s %s", Fg(T.Dark, "STATUS:"), Fg(T.Neon, "CONVERGED TARGET LOCK")), radarW)

	raw := make([]string, 0, 13)
	raw = append(raw, r0)
	raw = append(raw, canvasLines...)
	raw = append(raw, r10, r11, r12)

	out := make([]string, len(raw))
	for i, line := range raw {
		out[i] = FitToWidth(line, radarW)
	}
	return out
}
