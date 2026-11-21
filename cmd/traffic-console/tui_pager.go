package main

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

// tuiPager scrolls the detail and health panes. Their lines arrive already
// wrapped to the pane, so unlike the bubbles viewport it does not measure
// every line for horizontal scrolling; on a large body that scan took most
// of each rebuild.
type tuiPager struct {
	lines         []string
	width, height int
	yOffset       int
}

func (p *tuiPager) SetWidth(width int)   { p.width = width }
func (p *tuiPager) SetHeight(height int) { p.height = height }
func (p tuiPager) Width() int            { return p.width }
func (p tuiPager) Height() int           { return p.height }
func (p tuiPager) YOffset() int          { return p.yOffset }
func (p tuiPager) TotalLineCount() int   { return len(p.lines) }
func (p tuiPager) maxYOffset() int       { return max(0, len(p.lines)-p.height) }

func (p *tuiPager) SetYOffset(n int) { p.yOffset = max(0, min(n, p.maxYOffset())) }
func (p *tuiPager) ScrollDown(n int) { p.SetYOffset(p.yOffset + n) }
func (p *tuiPager) ScrollUp(n int)   { p.SetYOffset(p.yOffset - n) }
func (p *tuiPager) GotoTop()         { p.yOffset = 0 }

// SetContentLines shows lines that fit the width, keeping the scroll
// position where the new content allows.
func (p *tuiPager) SetContentLines(lines []string) {
	p.lines = lines
	p.yOffset = min(p.yOffset, p.maxYOffset())
}
func (p tuiPager) GetContent() string { return strings.Join(p.lines, "\n") }

// Update scrolls on the pane's keys. Letters stay free for page actions; j
// and k reach the pager only on pages without records.
func (p tuiPager) Update(msg tea.Msg) (tuiPager, tea.Cmd) {
	press, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return p, nil
	}
	switch press.String() {
	case "pgdown":
		p.ScrollDown(p.height)
	case "pgup":
		p.ScrollUp(p.height)
	case "ctrl+d":
		p.ScrollDown(p.height / 2)
	case "ctrl+u":
		p.ScrollUp(p.height / 2)
	case "down", "j":
		p.ScrollDown(1)
	case "up", "k":
		p.ScrollUp(1)
	}
	return p, nil
}

// View draws the visible lines padded to the pane. A line wider than the
// pane, wrapped before a resize that has not been re-wrapped yet, is cut.
func (p tuiPager) View() string {
	if p.width <= 0 || p.height <= 0 {
		return ""
	}
	start := min(p.yOffset, len(p.lines))
	rows := make([]string, p.height)
	for i := range rows {
		line := ""
		if start+i < len(p.lines) {
			line = p.lines[start+i]
		}
		width := tuiWidth(line)
		if width > p.width {
			line = termansi.Truncate(line, p.width, "")
			width = tuiWidth(line)
		}
		rows[i] = line + strings.Repeat(" ", max(0, p.width-width))
	}
	return strings.Join(rows, "\n")
}
