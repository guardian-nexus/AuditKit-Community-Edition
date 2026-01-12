package cli

import (
	"fmt"
	"strings"
)

// Box characters for drawing
const (
	BoxTopLeft     = "┌"
	BoxTopRight    = "┐"
	BoxBottomLeft  = "└"
	BoxBottomRight = "┘"
	BoxHorizontal  = "─"
	BoxVertical    = "│"
	BoxTeeRight    = "├"
	BoxTeeLeft     = "┤"

	// Double line box
	BoxDoubleTopLeft     = "╔"
	BoxDoubleTopRight    = "╗"
	BoxDoubleBottomLeft  = "╚"
	BoxDoubleBottomRight = "╝"
	BoxDoubleHorizontal  = "═"
	BoxDoubleVertical    = "║"
)

// Box draws a box around text
type Box struct {
	width   int
	title   string
	content []string
	double  bool
	color   string
}

// NewBox creates a new box with specified width
func NewBox(width int) *Box {
	return &Box{
		width: width,
	}
}

// SetTitle sets the box title
func (b *Box) SetTitle(title string) *Box {
	b.title = title
	return b
}

// SetDouble uses double-line box characters
func (b *Box) SetDouble(double bool) *Box {
	b.double = double
	return b
}

// SetColor sets the box color
func (b *Box) SetColor(color string) *Box {
	b.color = color
	return b
}

// AddLine adds a line to the box
func (b *Box) AddLine(line string) *Box {
	b.content = append(b.content, line)
	return b
}

// AddSeparator adds a separator line
func (b *Box) AddSeparator() *Box {
	b.content = append(b.content, "---SEPARATOR---")
	return b
}

// String renders the box to a string
func (b *Box) String() string {
	var sb strings.Builder

	tl, tr, bl, br, h, v := BoxTopLeft, BoxTopRight, BoxBottomLeft, BoxBottomRight, BoxHorizontal, BoxVertical
	if b.double {
		tl, tr, bl, br, h, v = BoxDoubleTopLeft, BoxDoubleTopRight, BoxDoubleBottomLeft, BoxDoubleBottomRight, BoxDoubleHorizontal, BoxDoubleVertical
	}

	color := b.color
	if color == "" {
		color = ""
	}

	// Top border with optional title
	if b.title != "" {
		titleLen := len(b.title) + 2 // add spaces around title
		leftPad := (b.width - 2 - titleLen) / 2
		rightPad := b.width - 2 - titleLen - leftPad
		sb.WriteString(color)
		sb.WriteString(tl)
		sb.WriteString(strings.Repeat(h, leftPad))
		sb.WriteString(" " + b.title + " ")
		sb.WriteString(strings.Repeat(h, rightPad))
		sb.WriteString(tr)
		sb.WriteString(Reset + "\n")
	} else {
		sb.WriteString(color)
		sb.WriteString(tl)
		sb.WriteString(strings.Repeat(h, b.width-2))
		sb.WriteString(tr)
		sb.WriteString(Reset + "\n")
	}

	// Content lines
	for _, line := range b.content {
		if line == "---SEPARATOR---" {
			sb.WriteString(color)
			sb.WriteString(BoxTeeRight)
			sb.WriteString(strings.Repeat(h, b.width-2))
			sb.WriteString(BoxTeeLeft)
			sb.WriteString(Reset + "\n")
		} else {
			// Pad or truncate line to fit
			displayLine := line
			lineLen := visibleLength(line)
			contentWidth := b.width - 4 // account for "│ " and " │"

			if lineLen > contentWidth {
				// Truncate
				displayLine = truncateWithEllipsis(line, contentWidth)
			}

			padding := contentWidth - visibleLength(displayLine)
			if padding < 0 {
				padding = 0
			}

			sb.WriteString(color)
			sb.WriteString(v)
			sb.WriteString(Reset)
			sb.WriteString(" " + displayLine + strings.Repeat(" ", padding) + " ")
			sb.WriteString(color)
			sb.WriteString(v)
			sb.WriteString(Reset + "\n")
		}
	}

	// Bottom border
	sb.WriteString(color)
	sb.WriteString(bl)
	sb.WriteString(strings.Repeat(h, b.width-2))
	sb.WriteString(br)
	sb.WriteString(Reset + "\n")

	return sb.String()
}

// Print prints the box to stdout
func (b *Box) Print() {
	fmt.Print(b.String())
}

// visibleLength calculates visible length excluding ANSI codes
func visibleLength(s string) int {
	inEscape := false
	length := 0
	for _, r := range s {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		length++
	}
	return length
}

// truncateWithEllipsis truncates a string to fit width with ellipsis
func truncateWithEllipsis(s string, width int) string {
	if width <= 3 {
		return "..."
	}

	result := ""
	length := 0
	inEscape := false

	for _, r := range s {
		if r == '\033' {
			inEscape = true
			result += string(r)
			continue
		}
		if inEscape {
			result += string(r)
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		if length >= width-3 {
			break
		}
		result += string(r)
		length++
	}

	return result + "..."
}

// SummaryBox creates a formatted summary box for scan results
func SummaryBox(provider, accountID, framework string, score float64, passed, failed, total int) string {
	box := NewBox(50).SetDouble(true).SetTitle("SCAN SUMMARY")

	box.AddLine(fmt.Sprintf("Provider:   %s", strings.ToUpper(provider)))
	box.AddLine(fmt.Sprintf("Account:    %s", accountID))
	box.AddLine(fmt.Sprintf("Framework:  %s", strings.ToUpper(framework)))
	box.AddSeparator()
	box.AddLine(fmt.Sprintf("Score:      %s", FormatScore(score)))
	box.AddLine(fmt.Sprintf("Passed:     %s%d%s", Green, passed, Reset))
	box.AddLine(fmt.Sprintf("Failed:     %s%d%s", Red, failed, Reset))
	box.AddLine(fmt.Sprintf("Total:      %d", total))

	return box.String()
}

// ResultTable formats controls in a table
func ResultTable(controls []struct{ ID, Name, Status, Severity string }) {
	if len(controls) == 0 {
		return
	}

	// Header
	fmt.Printf("\n%-12s %-40s %-8s %-10s\n", "CONTROL", "NAME", "STATUS", "SEVERITY")
	fmt.Println(strings.Repeat("-", 72))

	// Rows
	for _, c := range controls {
		name := c.Name
		if len(name) > 38 {
			name = name[:35] + "..."
		}

		status := FormatStatus(c.Status)
		severity := FormatSeverity(c.Severity)

		fmt.Printf("%-12s %-40s %s %s\n", c.ID, name, status, severity)
	}
}
