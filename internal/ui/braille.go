package ui

import (
	"math"
	"strings"
)

// brailleDotMap maps sub-pixel offset (row 0..3, col 0..1) to Unicode Braille bitmask.
// Unicode Braille starts at 0x2800.
// Standard dot numbering:
// (0,0): 0x01   (1,0): 0x08
// (0,1): 0x02   (1,1): 0x10
// (0,2): 0x04   (1,2): 0x20
// (0,3): 0x40   (1,3): 0x80
var brailleDotMap = [4][2]byte{
	{0x01, 0x08},
	{0x02, 0x10},
	{0x04, 0x20},
	{0x40, 0x80},
}

// BrailleCanvas is a high-resolution sub-pixel terminal raster canvas.
// Each text character cell holds a 2x4 grid of sub-pixels using Unicode Braille patterns (U+2800..U+28FF),
// providing 8x visual resolution over traditional text blocks.
type BrailleCanvas struct {
	cols    int
	rows    int
	pixelW  int
	pixelH  int
	grid    [][]byte   // [row][col] bitmask
	palette [][]string // [row][col] optional ANSI style
}

// NewBrailleCanvas creates a new raster canvas with the given character cell dimensions.
func NewBrailleCanvas(cols, rows int) *BrailleCanvas {
	grid := make([][]byte, rows)
	palette := make([][]string, rows)
	for r := 0; r < rows; r++ {
		grid[r] = make([]byte, cols)
		palette[r] = make([]string, cols)
	}
	return &BrailleCanvas{
		cols:    cols,
		rows:    rows,
		pixelW:  cols * 2,
		pixelH:  rows * 4,
		grid:    grid,
		palette: palette,
	}
}

// PixelWidth returns total horizontal sub-pixels.
func (c *BrailleCanvas) PixelWidth() int { return c.pixelW }

// PixelHeight returns total vertical sub-pixels.
func (c *BrailleCanvas) PixelHeight() int { return c.pixelH }

// Clear resets the canvas to all blank dots.
func (c *BrailleCanvas) Clear() {
	for r := 0; r < c.rows; r++ {
		for col := 0; col < c.cols; col++ {
			c.grid[r][col] = 0
			c.palette[r][col] = ""
		}
	}
}

// Set turns on a sub-pixel at (x, y).
func (c *BrailleCanvas) Set(x, y int) {
	if x < 0 || x >= c.pixelW || y < 0 || y >= c.pixelH {
		return
	}
	col := x / 2
	row := y / 4
	subX := x % 2
	subY := y % 4
	c.grid[row][col] |= brailleDotMap[subY][subX]
}

// SetColor sets the active color for the cell containing (x, y).
func (c *BrailleCanvas) SetColor(x, y int, color string) {
	if x < 0 || x >= c.pixelW || y < 0 || y >= c.pixelH {
		return
	}
	col := x / 2
	row := y / 4
	c.palette[row][col] = color
}

// Unset turns off a sub-pixel at (x, y).
func (c *BrailleCanvas) Unset(x, y int) {
	if x < 0 || x >= c.pixelW || y < 0 || y >= c.pixelH {
		return
	}
	col := x / 2
	row := y / 4
	subX := x % 2
	subY := y % 4
	c.grid[row][col] &^= brailleDotMap[subY][subX]
}

// DrawLine draws a line using Bresenham's line algorithm.
func (c *BrailleCanvas) DrawLine(x0, y0, x1, y1 int) {
	dx := int(math.Abs(float64(x1 - x0)))
	dy := -int(math.Abs(float64(y1 - y0)))
	sx := 1
	if x0 >= x1 {
		sx = -1
	}
	sy := 1
	if y0 >= y1 {
		sy = -1
	}
	errVal := dx + dy

	for {
		c.Set(x0, y0)
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * errVal
		if e2 >= dy {
			errVal += dy
			x0 += sx
		}
		if e2 <= dx {
			errVal += dx
			y0 += sy
		}
	}
}

// DrawCircle plots a circle using the midpoint circle algorithm.
func (c *BrailleCanvas) DrawCircle(cx, cy, r int) {
	x := 0
	y := r
	d := 1 - r
	c.drawSymmetric8(cx, cy, x, y)
	for x < y {
		x++
		if d < 0 {
			d += 2*x + 1
		} else {
			y--
			d += 2*(x-y) + 1
		}
		c.drawSymmetric8(cx, cy, x, y)
	}
}

func (c *BrailleCanvas) drawSymmetric8(cx, cy, x, y int) {
	c.Set(cx+x, cy+y)
	c.Set(cx-x, cy+y)
	c.Set(cx+x, cy-y)
	c.Set(cx-x, cy-y)
	c.Set(cx+y, cy+x)
	c.Set(cx-y, cy+x)
	c.Set(cx+y, cy-x)
	c.Set(cx-y, cy-x)
}

// DrawDashedCircle draws a circular ring broken into segments with continuous rotation phase.
func (c *BrailleCanvas) DrawDashedCircle(cx, cy, r int, segments int, phase float64) {
	steps := int(2.0 * math.Pi * float64(r) * 1.5)
	if steps < 36 {
		steps = 36
	}
	for i := 0; i < steps; i++ {
		theta := float64(i) * 2.0 * math.Pi / float64(steps)
		if math.Sin(float64(segments)*(theta+phase)) > 0.0 {
			px := int(float64(cx) + float64(r)*math.Cos(theta) + 0.5)
			py := int(float64(cy) + float64(r)*math.Sin(theta) + 0.5)
			c.Set(px, py)
		}
	}
}

// DrawRay draws a beam from center (cx, cy) to distance r along angle theta.
func (c *BrailleCanvas) DrawRay(cx, cy, r int, theta float64) {
	x1 := int(float64(cx) + float64(r)*math.Cos(theta) + 0.5)
	y1 := int(float64(cy) + float64(r)*math.Sin(theta) + 0.5)
	c.DrawLine(cx, cy, x1, y1)
}

// DrawRadarSweep draws a rotating beam with a fading phosphor wake sector.
func (c *BrailleCanvas) DrawRadarSweep(cx, cy, r int, sweepAngle float64, wakeRadians float64) {
	// Draw main sweep ray
	c.DrawRay(cx, cy, r, sweepAngle)

	// Draw phosphor wake sector with decaying dot density
	numRays := 16
	for i := 1; i <= numRays; i++ {
		frac := float64(i) / float64(numRays)
		trailAngle := sweepAngle - frac*wakeRadians
		// Density decreases as we move away from the main beam
		stepCount := int(float64(r) * (1.0 - frac*0.7))
		for d := 1; d <= stepCount; d++ {
			// Sub-sample to produce authentic analog CRT phosphor decay texture
			if (d+i)%3 != 0 {
				px := int(float64(cx) + float64(d)*math.Cos(trailAngle) + 0.5)
				py := int(float64(cy) + float64(d)*math.Sin(trailAngle) + 0.5)
				c.Set(px, py)
			}
		}
	}
}

// DrawCrosshair draws reticle crosshairs centered at (cx, cy).
func (c *BrailleCanvas) DrawCrosshair(cx, cy, size, gap int) {
	if size <= gap {
		return
	}
	// Left & Right
	c.DrawLine(cx-size, cy, cx-gap, cy)
	c.DrawLine(cx+gap, cy, cx+size, cy)
	// Top & Bottom
	c.DrawLine(cx, cy-size, cx, cy-gap)
	c.DrawLine(cx, cy+gap, cx, cy+size)
}

// DrawBlip draws a pulsing threat blip at (cx + r*cos(theta), cy + r*sin(theta)).
func (c *BrailleCanvas) DrawBlip(cx, cy, r int, theta float64, size int) {
	bx := int(float64(cx) + float64(r)*math.Cos(theta) + 0.5)
	by := int(float64(cy) + float64(r)*math.Sin(theta) + 0.5)
	for dx := -size; dx <= size; dx++ {
		for dy := -size; dy <= size; dy++ {
			c.Set(bx+dx, by+dy)
		}
	}
}

// Render converts the Braille canvas into an array of string lines.
// An empty cell is rendered as a space ' ', and non-empty cells are rendered
// with Unicode Braille rune (0x2800 | mask).
func (c *BrailleCanvas) Render(defaultColor string) []string {
	lines := make([]string, c.rows)
	for r := 0; r < c.rows; r++ {
		lines[r] = c.RenderRowRange(r, 0, c.cols, defaultColor)
	}
	return lines
}

// RenderRowRange converts a column range [startCol, endCol) of row r into a string,
// correctly applying colors per-cell without slicing formatted strings or ANSI codes.
func (c *BrailleCanvas) RenderRowRange(r, startCol, endCol int, defaultColor string) string {
	if r < 0 || r >= c.rows {
		return ""
	}
	if startCol < 0 {
		startCol = 0
	}
	if endCol > c.cols {
		endCol = c.cols
	}
	var sb strings.Builder
	for col := startCol; col < endCol; col++ {
		mask := c.grid[r][col]
		if mask == 0 {
			sb.WriteString(" ")
			continue
		}
		ch := string(rune(0x2800 | int(mask)))
		color := c.palette[r][col]
		if color == "" {
			color = defaultColor
		}
		if color != "" {
			sb.WriteString(Fg(color, ch))
		} else {
			sb.WriteString(ch)
		}
	}
	return sb.String()
}
