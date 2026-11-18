package ui

import "fmt"

// RenderConstellation renders an animated AST dependency graph matching
// the left-hand column panels in image copy.png, complete with packet transmission pulses.
func RenderConstellation(step int) []string {
	n1, n2, n3, n4 := "◈", "◈", "◈", "◈"
	if !Sym.Unicode {
		n1, n2, n3, n4 = "o", "*", "o", "*"
	}

	// Packet flow animation along transmission wires
	wirePhase := step % 4
	w1, w2 := "───", "───"
	switch wirePhase {
	case 0:
		w1 = "─>─"
		w2 = "───"
	case 1:
		w1 = "──>"
		w2 = "─>─"
	case 2:
		w1 = "───"
		w2 = "──>"
	case 3:
		w1 = "───"
		w2 = "───"
	}

	nodeCol1 := Paint(n1, T.Neon, T.Bold)
	nodeCol2 := Paint(n2, T.Cyan, T.Bold)
	nodeCol3 := Paint(n3, T.Amber, T.Bold)
	nodeCol4 := Paint(n4, T.Primary)

	line1 := fmt.Sprintf("%s%s%s%s%s [AST MESH]", nodeCol1, Fg(T.Neon, w1), nodeCol2, Fg(T.Dark, "───"), nodeCol3)
	line2 := fmt.Sprintf("%s       %s       %s   PACKETS: 4.8k/s", Fg(T.Dark, "│"), Fg(T.Dark, "│"), Fg(T.Dark, "│"))
	line3 := fmt.Sprintf("%s%s%s%s%s NODES: 42 ACTIVE", nodeCol4, Fg(T.Dark, "───"), nodeCol1, Fg(T.Cyan, w2), nodeCol2)

	return []string{
		line1,
		line2,
		line3,
		fmt.Sprintf("GRAPH TOPOLOGY: CYCLIC DIRECTED (DEPTH: %d)", (step%5)+3),
	}
}
