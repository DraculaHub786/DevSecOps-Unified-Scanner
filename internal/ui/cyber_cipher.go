package ui

import (
	"fmt"
	"math/rand"
	"strings"
)

var cipherHexRunes = []rune("0123456789ABCDEF")
var cyberGlintRunes = []rune("0123456789ABCDEF#%&*<>§λΩψ")

// RenderCipherStream renders the cryptographic token decryption block matching
// the top-right HUD section of image copy.png, featuring animated character tumbling
// and rolling entropy streams inspired by TerminalTextEffects.
func RenderCipherStream(targetWord string, progress float64, step int, width int) []string {
	if targetWord == "" {
		targetWord = "SENTINEL-X9"
	}
	targetRunes := []rune(targetWord)
	total := len(targetRunes)

	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}

	solvedCount := int(float64(total)*progress + 0.5)
	if solvedCount > total {
		solvedCount = total
	}

	// Deterministic random seed tied to step for consistent frame rendering
	r := rand.New(rand.NewSource(int64(step*7919 + 1337)))

	// 1. Boxed Token Stream: [ S ][ E ][ N ][ T ] ...
	var tokenBoxes strings.Builder
	for i := 0; i < total; i++ {
		if i < solvedCount {
			// Decrypted & locked character (Glowing Neon)
			tokenBoxes.WriteString(Paint(fmt.Sprintf("[%c]", targetRunes[i]), T.Neon, T.Bold))
		} else if i == solvedCount && progress < 1.0 {
			// Actively resolving character (Flickering Cyan/White glitch)
			glint := cyberGlintRunes[r.Intn(len(cyberGlintRunes))]
			tokenBoxes.WriteString(Paint(fmt.Sprintf("[%c]", glint), T.CyanBright, T.Bold))
		} else {
			// Masked unencrypted character (Muted Dark)
			tokenBoxes.WriteString(Fg(T.Dark, "[·]"))
		}
		if i < total-1 {
			tokenBoxes.WriteString(" ")
		}
	}

	pct := int(progress * 100)
	statusText := fmt.Sprintf("DECRYPTING CODE VECTORS... %2d%%", pct)
	if progress >= 1.0 {
		statusText = "CRYPTOGRAPHIC TELEMETRY CONVERGED"
	}

	// 2. Rolling cryptographic hash telemetry
	hashBytes := make([]byte, 8)
	for i := range hashBytes {
		hashBytes[i] = byte(cipherHexRunes[r.Intn(len(cipherHexRunes))])
	}
	hashStr := string(hashBytes)
	entropyVal := 7.42 + float64(step%10)*0.05
	hashTelemetry := fmt.Sprintf("HASH: 0x%s.. [ENTROPY: %.2f]", hashStr, entropyVal)

	return []string{
		Fg(T.Cyan, statusText),
		tokenBoxes.String(),
		Fg(T.Dark, hashTelemetry),
	}
}
