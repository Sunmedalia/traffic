package main

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

func (m tuiModel) aggLen() int {
	sum := m.currentSummary()
	switch {
	case sum == nil:
		return 0
	case m.alertView == viewRules:
		return len(sum.Rules)
	}
	return len(sum.Sources)
}
func tuiMove(selected *int, key string, n, pageSize int) bool {
	switch key {
	case "up", "k":
		*selected--
	case "down", "j":
		*selected++
	case "home", "g":
		*selected = 0
	case "end", "G":
		*selected = n - 1
	case "pgup", "left", "p":
		*selected -= pageSize
	case "pgdown", "right", "n":
		*selected += pageSize
	default:
		return false
	}
	*selected = max(0, min(n-1, *selected))
	return true
}

func (m *tuiModel) updateAggKey(key string) tea.Cmd {
	sum := m.currentSummary()
	n := m.aggLen()
	selected := &m.aggSelected[m.alertView]
	if tuiMove(selected, key, n, max(1, m.contentHeight()-4)) {
		return nil
	}
	if key != "enter" || sum == nil || *selected >= n {
		if key == "e" || key == "c" || key == "m" || key == "H" {
			m.flash = "按 Enter 进入逐条视图后可用"
		}
		return nil
	}
	filter := m.filter
	if m.alertView == viewRules {
		filter.Rule = sum.Rules[*selected].Rule
	} else {
		filter.Client = sum.Sources[*selected].Client
	}
	return m.drillTo(tabAlerts, filter)
}

// alertsView puts the view switcher above the rule, source or record list.
func (m tuiModel) alertsView(width, height int) string {
	names := [alertViewCount]string{"按规则", "按来源", "逐条"}
	parts := []string{}
	for i, name := range names {
		part := tuiMuted.Render(" " + name + " ")
		if i == m.alertView {
			part = tuiAccent.Render("[" + name + "]")
		}
		parts = append(parts, tuiHit(fmt.Sprintf("aview:%d", i), part))
	}
	selector := tuiSpread(tuiMuted.Render("视图 ")+strings.Join(parts, " "), tuiMuted.Render(tuiHints("v 切换视图")), width)
	height = max(1, height-1)
	if m.alertView == viewList {
		return selector + "\n" + m.listView(width, height)
	}
	return selector + "\n" + m.aggTable(width, height)
}

func (m tuiModel) aggTable(width, height int) string {
	sum := m.currentSummary()
	if sum == nil {
		return "正在统计告警…"
	}
	n := m.aggLen()
	if n == 0 {
		if m.filter != (tuiFilter{}) {
			return "当前筛选无告警，按 x 清空筛选"
		}
		return "暂无告警"
	}
	now := time.Now()
	today := true
	timeOf := func(i int) []string {
		if m.alertView == viewRules {
			return []string{sum.Rules[i].Last}
		}
		return []string{sum.Sources[i].First, sum.Sources[i].Last}
	}
	labelWidth := 12
	for i := 0; i < n; i++ {
		for _, t := range timeOf(i) {
			today = today && tuiIsToday(t, now)
		}
		label := ""
		if m.alertView == viewRules {
			label = sum.Rules[i].Rule
		} else {
			label = sum.Sources[i].Client
		}
		labelWidth = max(labelWidth, min(41, len([]rune(tuiLine(label)))+2))
	}
	timeWidth := 15
	if today {
		timeWidth = 10
	}
	header := ""
	if m.alertView == viewRules {
		header = tuiCell("规则", labelWidth) + tuiCell("级别", 6) + tuiCell("命中", 8) + tuiCell("来源", 8) + tuiCell("最近", timeWidth) + "最近一次匹配"
	} else {
		header = tuiCell("客户端", labelWidth) + tuiCell("命中", 8) + tuiCell("规则数", 8) + tuiCell("首次", timeWidth) + tuiCell("最近", timeWidth) + "规则"
	}
	lines := []string{tuiMuted.Render(termansi.Truncate(header, width, "…"))}
	visible := max(1, height-2)
	selected := min(m.aggSelected[m.alertView], n-1)
	start := max(0, selected-visible+1)
	for i := start; i < min(n, start+visible); i++ {
		row := ""
		if m.alertView == viewRules {
			r := sum.Rules[i]
			row = tuiCell(tuiLine(r.Rule), labelWidth) + tuiSeverityStyle(r.Severity).Render(tuiCell(tuiSeverity(r.Severity), 6)) + tuiCell(tuiCount(uint64(r.Hits)), 8) + tuiCell(fmt.Sprint(r.Sources), 8) + tuiCell(tuiShortTime(r.Last, today), timeWidth) + tuiMuted.Render(tuiLine(r.Match))
		} else {
			src := sum.Sources[i]
			row = tuiCell(tuiLine(src.Client), labelWidth) + tuiCell(tuiCount(uint64(src.Hits)), 8) + tuiCell(fmt.Sprint(len(src.Rules)), 8) + tuiCell(tuiShortTime(src.First, today), timeWidth) + tuiCell(tuiShortTime(src.Last, today), timeWidth) + tuiMuted.Render(tuiLine(strings.Join(src.Rules, ", ")))
		}
		if i == selected {
			row = tuiSelected.Render(tuiCell(termansi.Strip(row), width))
		}
		lines = append(lines, tuiHit(fmt.Sprintf("agg:%d", i), tuiCell(row, width)))
	}
	for len(lines) < height-1 {
		lines = append(lines, "")
	}
	footer := ""
	if m.alertView == viewRules {
		footer = fmt.Sprintf("%d 条规则 · 告警请求 %s · 级别高的在前，同级按命中数 · Enter 查看逐条", n, tuiCount(uint64(sum.AlertRequests)))
	} else {
		footer = fmt.Sprintf("%d 个来源 · 告警请求 %s · 按命中数排序 · Enter 查看逐条", n, tuiCount(uint64(sum.AlertRequests)))
		if sum.SourcesCapped {
			footer += fmt.Sprintf(" · 仅显示前 %d 个", tuiSourceLimit)
		}
	}
	return strings.Join(append(lines, tuiMuted.Render(termansi.Truncate(footer, width, "…"))), "\n")
}
