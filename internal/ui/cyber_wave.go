package ui

import (
	"fmt"
	"math"
	"strings"
)

var waveBlocks = []rune(" ▂▃▄▅▆▇█")

// RenderWaveform generates an animated oscilloscope audio/signal frequency waveform
// matching the bottom-right and top-left telemetry panels of image copy.png.
func RenderWaveform(step int, width int, entropy float64) []string {
	if width <= 0 {
		width = 32
	}

	var wave1 strings.Builder
	var wave2 strings.Builder

	// Primary Fourier multi-harmonic frequency wave
	for i := 0; i < width; i++ {
		angle1 := float64(i)*0.28 - float64(step)*0.35
		angle2 := float64(i)*0.55 + float64(step)*0.20
		angle3 := float64(i)*1.10 - float64(step)*0.10

		val := math.Sin(angle1)*0.50 + math.Cos(angle2)*0.30 + math.Sin(angle3)*0.20
		norm := (val + 1.0) / 2.0
		if norm < 0 {
			norm = 0
		}
		if norm > 1 {
			norm = 1
		}
		idx := int(norm * float64(len(waveBlocks)-1))
		wave1.WriteRune(waveBlocks[idx])
	}

	// Secondary acoustic spectrum pulse wave
	for i := 0; i < width; i++ {
		angle := float64(i)*0.18 + float64(step)*0.25
		val := math.Abs(math.Sin(angle)*math.Cos(angle*0.5))
		idx := int(val * float64(len(waveBlocks)-1))
		wave2.WriteRune(waveBlocks[idx])
	}

	db := -12.4 + math.Mod(float64(step*3), 18.0)
	freqGhz := 7.84 + math.Sin(float64(step)*0.2)*0.12

	telemetryLine := fmt.Sprintf("%s %s  %s",
		Paint("SIGNAL SPECTRUM:", T.Cyan),
		Paint(fmt.Sprintf("%.2f GHz", freqGhz), T.Neon, T.Bold),
		Fg(T.Dark, fmt.Sprintf("[PEAK: %.1f dB]", db)),
	)

	return []string{
		telemetryLine,
		Paint(wave1.String(), T.Neon),
		Fg(T.Muted, wave2.String()),
	}
}

// RenderStaticWaveform renders a static entropy/risk waveform for report overview.
func RenderStaticWaveform(width int, riskScore float64) string {
	if width <= 0 {
		width = 24
	}
	var b strings.Builder
	for i := 0; i < width; i++ {
		angle := float64(i) * 0.45
		val := (math.Sin(angle)*0.6 + math.Cos(angle*0.3)*0.4 + 1.0) / 2.0
		if val < 0 {
			val = 0
		}
		if val > 1 {
			val = 1
		}
		idx := int(val * float64(len(waveBlocks)-1))
		b.WriteRune(waveBlocks[idx])
	}
	return Paint(b.String(), T.Neon)
}
