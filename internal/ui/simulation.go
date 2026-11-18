package ui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LiveHUD controls the real-time dynamic cybersecurity HUD animation
// during project scanning.
type LiveHUD struct {
	mu           sync.Mutex
	running      bool
	repoPath     string
	startTime    time.Time
	step         int
	prevLines    int
	targetWord   string
	activeFile   string
	findingCount int
	critCount    int
	highCount    int
	medCount     int
	lowCount     int
	stageText    string
	progressPct  float64
	engines      map[string]string // engine -> status string
	doneChan     chan struct{}
}

// NewLiveHUD creates a new dynamic scanner HUD controller.
func NewLiveHUD(repoPath string) *LiveHUD {
	return &LiveHUD{
		repoPath:    repoPath,
		startTime:   time.Now(),
		targetWord:  "SENTINEL-X9",
		activeFile:  "Initializing security engine matrices...",
		stageText:   "DISCOVERING WORKSPACE",
		progressPct: 0.05,
		engines: map[string]string{
			"SAST":    "QUEUED",
			"SECRETS": "QUEUED",
			"SCA":     "QUEUED",
			"IAC":     "QUEUED",
			"DAST":    "STANDBY",
			"RESIL":   "READY",
		},
		doneChan: make(chan struct{}),
	}
}

// Start launches the dynamic HUD refresh loop in a background goroutine.
func (h *LiveHUD) Start(ctx context.Context) {
	if !IsInteractive() {
		return
	}

	h.mu.Lock()
	h.running = true
	h.startTime = time.Now()
	h.mu.Unlock()

	// Switch to alternate screen buffer, clear screen, home cursor, and hide cursor.
	// This ensures the scanning animation updates 100% in-place without scrolling or terminal spam.
	fmt.Print("\033[?1049h\033[2J\033[H\033[?25l")

	go func() {
		ticker := time.NewTicker(75 * time.Millisecond) // ~13.3 FPS
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				h.Stop()
				return
			case <-h.doneChan:
				return
			case <-ticker.C:
				h.mu.Lock()
				if !h.running {
					h.mu.Unlock()
					return
				}
				h.step++
				frame := h.renderFrame()
				h.draw(frame)
				h.mu.Unlock()
			}
		}
	}()
}

// UpdateProgress updates the active scanning status thread-safely.
func (h *LiveHUD) UpdateProgress(stage string, detail string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if stage != "" {
		h.stageText = strings.ToUpper(stage)
	}

	if detail != "" {
		h.activeFile = detail
		// If detail contains finding hints
		if strings.Contains(strings.ToLower(detail), "finding") || strings.Contains(strings.ToLower(detail), "flaw") {
			h.findingCount++
		}
	}

	switch stage {
	case "discovery":
		h.engines["SAST"] = "INIT"
		h.engines["SECRETS"] = "INIT"
		h.engines["SCA"] = "INIT"
		h.progressPct = 0.15
	case "engine_start":
		name := strings.ToUpper(detail)
		if strings.Contains(name, "SEMGREP") || strings.Contains(name, "SAST") {
			h.engines["SAST"] = "RUNNING"
		} else if strings.Contains(name, "GITLEAKS") || strings.Contains(name, "SECRET") {
			h.engines["SECRETS"] = "ACTIVE"
		} else if strings.Contains(name, "OSV") || strings.Contains(name, "SCA") {
			h.engines["SCA"] = "ANALYZING"
		} else if strings.Contains(name, "TRIVY") || strings.Contains(name, "IAC") {
			h.engines["IAC"] = "RUNNING"
		} else if strings.Contains(name, "NUCLEI") || strings.Contains(name, "DAST") {
			h.engines["DAST"] = "PROBING"
		}
		if h.progressPct < 0.85 {
			h.progressPct += 0.12
		}
	case "engine_done":
		name := strings.ToUpper(detail)
		if strings.Contains(name, "SEMGREP") || strings.Contains(name, "SAST") {
			h.engines["SAST"] = "DONE"
		} else if strings.Contains(name, "GITLEAKS") || strings.Contains(name, "SECRET") {
			h.engines["SECRETS"] = "LOCKED"
		} else if strings.Contains(name, "OSV") || strings.Contains(name, "SCA") {
			h.engines["SCA"] = "DONE"
		} else if strings.Contains(name, "TRIVY") || strings.Contains(name, "IAC") {
			h.engines["IAC"] = "DONE"
		} else if strings.Contains(name, "NUCLEI") || strings.Contains(name, "DAST") {
			h.engines["DAST"] = "DONE"
		}
		if h.progressPct < 0.95 {
			h.progressPct += 0.08
		}
	case "correlate":
		h.stageText = "CORRELATING RISK MATRIX"
		h.progressPct = 0.95
	}
}

// SetFindings updates the detected findings telemetry.
func (h *LiveHUD) SetFindings(crit, high, med, low int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.critCount = crit
	h.highCount = high
	h.medCount = med
	h.lowCount = low
	h.findingCount = crit + high + med + low
}

// Stop cleanly ends the live animation and displays the transition frame.
func (h *LiveHUD) Stop() {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	h.running = false
	close(h.doneChan)

	// Play transition frame in the alternate screen buffer
	transitionLines := h.renderTransition()
	h.draw(transitionLines)
	h.mu.Unlock()

	// Allow human eye to appreciate the matrix convergence
	time.Sleep(550 * time.Millisecond)

	h.mu.Lock()
	// Exit alternate screen buffer, restoring normal terminal, and show cursor
	fmt.Print("\033[?1049l\033[?25h")
	h.prevLines = 0
	h.mu.Unlock()

	// Print sleek transition banner in normal terminal buffer
	pw := GetPanelWidth()
	badge := Paint(" « SENTINEL // SCAN COMPLETE // DEPLOYING DEFENSE MATRIX REPORT » ", T.Neon, T.Bold)
	fmt.Printf("\n%s\n\n", Center(badge, pw))
}

func (h *LiveHUD) draw(lines []string) {
	var buf strings.Builder
	// Always position cursor at row 1, col 1 in alternate screen buffer
	buf.WriteString("\033[H")
	for _, l := range lines {
		buf.WriteString("\033[2K") // Clear line
		buf.WriteString(l)
		buf.WriteString("\r\n")
	}
	fmt.Print(buf.String())
	h.prevLines = len(lines)
}

func (h *LiveHUD) renderFrame() []string {
	elapsed := time.Since(h.startTime)
	timerStr := fmt.Sprintf("%02d:%02d.%02d",
		int(elapsed.Minutes()), int(elapsed.Seconds())%60, (elapsed.Milliseconds()%1000)/10)

	targetBase := filepath.Base(h.repoPath)
	if targetBase == "." || targetBase == "/" || targetBase == "\\" {
		targetBase = "WORKSPACE"
	}

	hudWidth := GetPanelWidth()

	// 1. Header Box (Width must exactly equal hudWidth)
	title := Paint(" SENTINEL // CYBERSECURITY RADAR HUD ", T.Neon, T.Bold)
	clock := Fg(T.CyanBright, "[ "+timerStr+" ]")
	topFill := hudWidth - 4 - VisibleWidth(title) - VisibleWidth(clock)
	if topFill < 1 {
		topFill = 1
	}
	line1 := fmt.Sprintf("%s%s%s%s%s",
		Fg(T.Dark, "╔═"), title, Fg(T.Dark, strings.Repeat("═", topFill)), clock, Fg(T.Dark, "═╗"))

	// 2. Sub-header: Target & DEFCON Status
	defcon := Paint("[ DEFCON-1: ACTIVE ]", T.RedBright, T.Bold)
	if h.findingCount == 0 {
		defcon = Paint("[ DEFCON-5: SECURE ]", T.Neon, T.Bold)
	}
	targetLine := Fg(T.Dark, " TARGET: ") + Fg(T.Bright, Trim(h.repoPath, 34))
	subFill := hudWidth - 2 - VisibleWidth(targetLine) - VisibleWidth(defcon)
	if subFill < 1 {
		subFill = 1
	}
	line2 := fmt.Sprintf("%s%s%s%s%s",
		Fg(T.Dark, "║"), targetLine, strings.Repeat(" ", subFill), defcon, Fg(T.Dark, "║"))

	divider := Fg(T.Dark, "╠"+strings.Repeat("═", hudWidth-2)+"╣")

	// 3. Central Dual-Panel: Left is Concentric Radar (34 cols), Right is Cipher + Waveform
	const radarW = 34
	maxRight := hudWidth - 40
	if maxRight < 24 {
		maxRight = 24
	}

	radarLines := RenderRadarFrame(h.step, h.findingCount, targetBase)
	cipherLines := RenderCipherStream(h.targetWord, h.progressPct, h.step, maxRight)
	waveLines := RenderWaveform(h.step, maxRight, 7.84)
	meshLines := RenderConstellation(h.step)

	// Right side: 13 rows aligned row-for-row with the 13 radar rows
	pctLabel := fmt.Sprintf("[ %2.0f%% ]", h.progressPct*100)
	rightRows := []string{
		FitToWidth(Fg(T.Cyan, "DECRYPTING SYSTEM MATRICES...")+" "+Paint(pctLabel, T.Neon, T.Bold), maxRight),
		FitToWidth(SegBar(h.progressPct, maxRight, T.Neon), maxRight),
		FitToWidth(cipherLines[1], maxRight),
		FitToWidth(cipherLines[2], maxRight),
		Fg(T.Dark, strings.Repeat("─", maxRight)),
		FitToWidth(waveLines[0], maxRight),
		FitToWidth(waveLines[1], maxRight),
		Fg(T.Dark, strings.Repeat("─", maxRight)),
		FitToWidth(meshLines[0], maxRight),
		FitToWidth(meshLines[2], maxRight),
		FitToWidth(Fg(T.Dark, "TARGET AST: ")+Fg(T.Bright, Trim(h.activeFile, maxRight-12)), maxRight),
		FitToWidth(Paint("DEFENSE POSTURE: DEFCON-1 ACTIVE", T.Neon), maxRight),
		FitToWidth(Paint("RADAR TELEMETRY: HIGH-RES VECTOR HUD", T.Neon), maxRight),
	}

	var centerRows []string
	for i := 0; i < len(radarLines) && i < len(rightRows); i++ {
		left := FitToWidth(radarLines[i], radarW)
		right := FitToWidth(rightRows[i], maxRight)
		row := fmt.Sprintf("%s %s  %s %s", Fg(T.Dark, "║"), left, right, Fg(T.Dark, "║"))
		centerRows = append(centerRows, row)
	}

	// 4. Engine Cockpit Matrix Row
	spinnerRunes := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
	spinner := string(spinnerRunes[h.step%len(spinnerRunes)])
	engLine := fmt.Sprintf(" %s SAST:%s  SEC:%s  SCA:%s  IAC:%s  DAST:%s",
		Fg(T.Neon, spinner),
		formatEnginePill(h.engines["SAST"]),
		formatEnginePill(h.engines["SECRETS"]),
		formatEnginePill(h.engines["SCA"]),
		formatEnginePill(h.engines["IAC"]),
		formatEnginePill(h.engines["DAST"]),
	)
	engRow := fmt.Sprintf("%s%s%s", Fg(T.Dark, "║"), FitToWidth(engLine, hudWidth-2), Fg(T.Dark, "║"))

	// 5. Active File Inspection Ticker
	fileTicker := fmt.Sprintf(" >>> %s: %s", Fg(T.Cyan, h.stageText), Fg(T.Bright, Trim(h.activeFile, hudWidth-20)))
	fileRow := fmt.Sprintf("%s%s%s", Fg(T.Dark, "║"), FitToWidth(fileTicker, hudWidth-2), Fg(T.Dark, "║"))

	// 6. Telemetry & Threat Metrics
	telemetry := fmt.Sprintf(" [SPEED: 5.2k L/s]  [CRIT:%s] [HIGH:%s] [MED:%s] [LOW:%s]",
		Paint(Itoa(h.critCount), T.Red, T.Bold),
		Paint(Itoa(h.highCount), T.Amber, T.Bold),
		Paint(Itoa(h.medCount), T.Cyan, T.Bold),
		Paint(Itoa(h.lowCount), T.Primary),
	)
	teleRow := fmt.Sprintf("%s%s%s", Fg(T.Dark, "║"), FitToWidth(telemetry, hudWidth-2), Fg(T.Dark, "║"))

	bottomLine := Fg(T.Dark, "╚"+strings.Repeat("═", hudWidth-2)+"╝")

	var all []string
	all = append(all, line1, line2, divider)
	all = append(all, centerRows...)
	all = append(all, divider, engRow, fileRow, teleRow, bottomLine)

	return all
}

func (h *LiveHUD) renderTransition() []string {
	hudWidth := GetPanelWidth()
	t1 := Paint(" [ 100% ] SCAN COMPLETE // ALL SECURITY MATRICES CONVERGED ", T.Neon, T.Bold)
	t2 := Fg(T.Cyan, " >>> SYNTHESIZING THREAT TELEMETRY & ATTACK SURFACES...")
	t3 := Fg(T.Bright, " >>> GENERATING COMPREHENSIVE CYBERSECURITY REPORT...")

	return []string{
		Fg(T.Dark, "╔"+strings.Repeat("═", hudWidth-2)+"╗"),
		fmt.Sprintf("%s%s%s", Fg(T.Dark, "║"), Center(t1, hudWidth-2), Fg(T.Dark, "║")),
		fmt.Sprintf("%s%s%s", Fg(T.Dark, "║"), FitToWidth("   "+t2, hudWidth-2), Fg(T.Dark, "║")),
		fmt.Sprintf("%s%s%s", Fg(T.Dark, "║"), FitToWidth("   "+t3, hudWidth-2), Fg(T.Dark, "║")),
		Fg(T.Dark, "╚"+strings.Repeat("═", hudWidth-2)+"╝"),
	}
}

func formatEnginePill(st string) string {
	switch st {
	case "RUNNING", "ACTIVE", "ANALYZING", "PROBING":
		return Paint(st, T.Neon, T.Bold)
	case "DONE", "LOCKED", "READY":
		return Fg(T.Primary, st)
	case "INIT":
		return Fg(T.Cyan, st)
	default:
		return Fg(T.Dark, st)
	}
}

// RunSimulationDemo executes an impressive, cinematic standalone cybersecurity
// scanning simulation of a project, highlighting the exact aesthetic of image copy.png.
func RunSimulationDemo(repoPath string) {
	if !IsInteractive() {
		fmt.Println("Interactive terminal required for scanning simulation.")
		return
	}

	hud := NewLiveHUD(repoPath)
	hud.Start(context.Background())

	steps := []struct {
		d     time.Duration
		stage string
		file  string
		c, h, m, l int
	}{
		{300 * time.Millisecond, "discovery", "Traversing AST dependency graph...", 0, 0, 0, 0},
		{400 * time.Millisecond, "engine_start", "Gitleaks 8.18.2: entropy secrets scan", 1, 0, 0, 0},
		{400 * time.Millisecond, "engine_start", "Semgrep 1.98.0: SAST AST rule evaluation", 1, 4, 1, 0},
		{400 * time.Millisecond, "engine_start", "OSV-Scanner 1.7.0: checking package lockfiles", 2, 12, 3, 1},
		{400 * time.Millisecond, "engine_start", "Trivy 0.58.0: container & IaC misconfigurations", 3, 22, 5, 2},
		{400 * time.Millisecond, "engine_done", "Analyzing tainted input vectors in server.js", 5, 28, 6, 3},
		{300 * time.Millisecond, "correlate", "Deduplicating cross-engine findings & scoring risk", 5, 31, 7, 3},
	}

	for _, s := range steps {
		time.Sleep(s.d)
		hud.SetFindings(s.c, s.h, s.m, s.l)
		hud.UpdateProgress(s.stage, s.file)
	}

	time.Sleep(300 * time.Millisecond)
	hud.Stop()
}
