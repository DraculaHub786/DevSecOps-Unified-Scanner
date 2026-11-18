package ui

import (
	"strings"
	"testing"
)

func TestRenderRadarFrame(t *testing.T) {
	for step := 0; step < 16; step++ {
		lines := RenderRadarFrame(step, 5, "testdata/vulnerable-app")
		if len(lines) == 0 {
			t.Fatalf("step %d returned no radar lines", step)
		}
		// Verify expected visual structure: equator degrees and counter-rotating indicators
		found090 := false
		foundRotation := false
		for _, l := range lines {
			if strings.Contains(l, "090°") {
				found090 = true
			}
			if strings.Contains(l, "CCW:MID") {
				foundRotation = true
			}
		}
		if !found090 {
			t.Errorf("step %d missing 090° marker", step)
		}
		if !foundRotation {
			t.Errorf("step %d missing CCW:MID counter-rotation telemetry", step)
		}
	}
}

func TestRenderStaticRadar(t *testing.T) {
	lines := RenderStaticRadar(10, "CRITICAL")
	if len(lines) < 6 {
		t.Fatalf("expected at least 6 lines for static radar, got %d", len(lines))
	}
	combined := strings.Join(lines, "\n")
	if !strings.Contains(combined, "RADAR LOCK") {
		t.Errorf("expected RADAR LOCK in static radar output, got:\n%s", combined)
	}
}

func TestRenderCipherStream(t *testing.T) {
	tests := []struct {
		word     string
		progress float64
		step     int
	}{
		{"SENTINEL", 0.0, 1},
		{"SENTINEL", 0.5, 5},
		{"SENTINEL", 1.0, 10},
		{"SECURITY", -0.1, 2},
		{"TEST", 1.5, 3},
	}

	for _, tt := range tests {
		lines := RenderCipherStream(tt.word, tt.progress, tt.step, 36)
		if len(lines) != 3 {
			t.Fatalf("expected 3 cipher lines, got %d", len(lines))
		}
		if tt.progress >= 1.0 {
			if !strings.Contains(lines[0], "CONVERGED") {
				t.Errorf("expected CONVERGED status for progress >= 1.0, got %s", lines[0])
			}
		}
	}
}

func TestRenderWaveform(t *testing.T) {
	lines := RenderWaveform(3, 30, 7.84)
	if len(lines) != 3 {
		t.Fatalf("expected 3 waveform lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "SPECTRUM") {
		t.Errorf("expected SPECTRUM in waveform output, got %s", lines[0])
	}
}

func TestRenderConstellation(t *testing.T) {
	for step := 0; step < 4; step++ {
		lines := RenderConstellation(step)
		if len(lines) != 4 {
			t.Fatalf("expected 4 constellation lines, got %d", len(lines))
		}
	}
}

func TestRenderStaticWaveform(t *testing.T) {
	wf := RenderStaticWaveform(20, 50.0)
	if wf == "" {
		t.Errorf("expected non-empty static waveform")
	}
}

func TestNewLiveHUD(t *testing.T) {
	hud := NewLiveHUD("test/repo")
	if hud == nil {
		t.Fatal("NewLiveHUD returned nil")
	}
	hud.UpdateProgress("discovery", "Scanning tree")
	hud.SetFindings(1, 2, 3, 4)
	if hud.findingCount != 10 {
		t.Errorf("expected findingCount 10, got %d", hud.findingCount)
	}

	// Verify HUD frame rows have uniform width matching GetPanelWidth()
	pw := GetPanelWidth()
	frames := hud.renderFrame()
	for i, f := range frames {
		vw := VisibleWidth(f)
		if vw != pw {
			t.Errorf("renderFrame row %d width = %d, expected %d. Line: %q", i, vw, pw, f)
		}
	}

	// Verify transition frame rows have uniform width matching GetPanelWidth()
	trans := hud.renderTransition()
	for i, f := range trans {
		vw := VisibleWidth(f)
		if vw != pw {
			t.Errorf("renderTransition row %d width = %d, expected %d. Line: %q", i, vw, pw, f)
		}
	}
}

func TestRadarFrameUniformWidth(t *testing.T) {
	for step := 0; step < 16; step++ {
		lines := RenderRadarFrame(step, 8, "test/workspace")
		for i, l := range lines {
			vw := VisibleWidth(l)
			if vw != 34 {
				t.Errorf("step %d row %d radar width = %d, expected 34. Line: %q", step, i, vw, l)
			}
		}
	}

	staticLines := RenderStaticRadar(12, "DEFCON-1")
	for i, l := range staticLines {
		vw := VisibleWidth(l)
		if vw != 34 {
			t.Errorf("static row %d radar width = %d, expected 34. Line: %q", i, vw, l)
		}
	}
}
