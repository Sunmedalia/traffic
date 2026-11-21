package main

// Text formatting and styling helpers shared by the TUI views.

import (
	lipgloss "charm.land/lipgloss/v2"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	termansi "github.com/charmbracelet/x/ansi"
)

func tuiClientHost(client string) string {
	if host, _, err := net.SplitHostPort(client); err == nil {
		return host
	}
	return client
}

// services offers the services this session probed, plus the active filter value.
func (m tuiModel) services() []string {
	seen := map[string]bool{}
	result := []string{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, target := range m.snapshot.Stats.Targets {
		add(target.Service)
	}
	if len(result) == 0 {
		for _, s := range []string{"nginx", "apache", "tomcat", "openssl", "iis"} {
			add(s)
		}
	}
	add(m.filter.Service)
	return result
}

func cleanTUIText(s string) string {
	s = termansi.Strip(strings.ToValidUTF8(s, "�"))
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r == '\n' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
func tuiLine(s string) string { return strings.ReplaceAll(cleanTUIText(s), "\n", " ") }
func tuiTime(s string) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return tuiIn(t).Format("01-02 15:04:05")
	}
	return tuiLine(s)
}

// tuiShortTime drops the date for records from today.
func tuiShortTime(s string, today bool) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil && today {
		return tuiIn(t).Format("15:04:05")
	}
	return tuiTime(s)
}
func tuiIsToday(s string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return false
	}
	y1, m1, d1 := tuiIn(t).Date()
	y2, m2, d2 := tuiIn(now).Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}
func tuiSeverity(s string) string {
	switch s {
	case "high":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	}
	return "—"
}
func tuiSeverityStyle(s string) lipgloss.Style {
	switch s {
	case "high":
		return tuiDanger
	case "medium":
		return tuiWarn
	case "low":
		return lipgloss.NewStyle()
	}
	return tuiMuted
}
func tuiState(s string) string {
	switch s {
	case "running":
		return "采集中"
	case "stopped":
		return "已停止"
	case "complete":
		return "已完成"
	case "failed":
		return "采集失败"
	case "stale":
		return "心跳过期"
	case "":
		return "未知"
	}
	return tuiLine(s)
}

// tuiStateBadge pairs a symbol with the state so it reads without color.
func tuiStateBadge(state string) string {
	label := tuiState(state)
	switch state {
	case "running":
		return tuiGood.Render("● " + label)
	case "stale":
		return tuiWarn.Render("! " + label)
	case "failed":
		return tuiDanger.Render("✕ " + label)
	case "complete", "stopped":
		return tuiMuted.Render("○ " + label)
	}
	return tuiMuted.Render("? " + label)
}
func tuiLive(state string) bool { return state == "running" || state == "stale" || state == "" }

func tuiStatusStyle(status int) lipgloss.Style {
	switch {
	case status == 0:
		return tuiMuted
	case status >= 500:
		return tuiDanger
	case status >= 400:
		return tuiWarn
	case status >= 200 && status < 300:
		return tuiGood
	}
	return lipgloss.NewStyle()
}
func tuiBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
func tuiCount(n uint64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// tuiCell fits text into a column by display width, so CJK text stays aligned.
func tuiCell(s string, width int) string {
	s = termansi.Truncate(s, width, "…")
	return s + strings.Repeat(" ", max(0, width-lipgloss.Width(s)))
}

// tuiWidth is the display width of one line. Printable ASCII is one cell per
// byte, which spares large bodies the grapheme scan.
func tuiWidth(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > '~' {
			return lipgloss.Width(s)
		}
	}
	return len(s)
}

// tuiPad pads a line that already fits width, as tuiCell does without
// measuring it twice.
func tuiPad(s string, width int) string {
	w := tuiWidth(s)
	if w > width {
		return tuiCell(s, width)
	}
	return s + strings.Repeat(" ", width-w)
}

// tuiWrap hard-wraps text to width and returns its lines. No character takes
// more cells than bytes, so a line that short already fits and skips the
// width scan; for a large body that scan is most of the wrapping cost.
func tuiWrap(text string, width int) []string {
	width = max(1, width)
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if len(line) <= width {
			continue
		}
		out := append(make([]string, 0, len(lines)+len(lines)/4), lines[:i]...)
		for _, line := range lines[i:] {
			if len(line) <= width {
				out = append(out, line)
				continue
			}
			out = append(out, strings.Split(termansi.Hardwrap(line, width, true), "\n")...)
		}
		return out
	}
	return lines
}

// tuiSpread places right-aligned text at the end of a line, dropping it when there is no room.
func tuiSpread(left, right string, width int) string {
	lw, rw := lipgloss.Width(left), lipgloss.Width(right)
	if lw+rw+2 > width {
		return termansi.Truncate(left, width, "…")
	}
	return left + strings.Repeat(" ", width-lw-rw) + right
}

// tuiUseUTC switches every displayed and typed time between local time and UTC,
// like the web page's time zone toggle.
var tuiUseUTC atomic.Bool

func tuiZone() *time.Location {
	if tuiUseUTC.Load() {
		return time.UTC
	}
	return time.Local
}
func tuiIn(t time.Time) time.Time { return t.In(tuiZone()) }
func tuiZoneLabel() string {
	if tuiUseUTC.Load() {
		return "UTC"
	}
	return "本地 " + time.Now().Format("MST -07:00")
}
