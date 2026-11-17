package main

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

var tuiBlockNames = [blockCount]string{"级别分布", "命中规则", "告警来源", "最近高危"}
var tuiLevelOrder = [3]string{"high", "medium", "low"}

// drillTo shows matching alerts one by one and remembers how to come back.
func (m *tuiModel) drillTo(filter tuiFilter) tea.Cmd {
	drill := &tuiDrill{tab: m.tab, view: m.alertView, filter: m.filter}
	if m.tab == tabOverview {
		drill.selected = m.blockSelected[m.block]
	} else {
		drill.selected = m.aggSelected[m.alertView]
	}
	m.tab, m.alertView = tabAlerts, viewList
	cmd := m.applyFilter(filter)
	m.drill = drill
	return cmd
}

// returnFromDrill restores the page, view, cursor and filter of the drill origin.
func (m *tuiModel) returnFromDrill() tea.Cmd {
	d := m.drill
	m.tab, m.alertView = d.tab, d.view
	if d.tab == tabOverview {
		m.blockSelected[m.block] = d.selected
	} else if d.view < viewList {
		m.aggSelected[d.view] = d.selected
	}
	return m.applyFilter(d.filter)
}

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
	return m.drillTo(filter)
}

func (m tuiModel) blockLen(sum *tuiSummary, block int) int {
	if sum == nil {
		return 0
	}
	switch block {
	case blockLevels:
		return len(tuiLevelOrder)
	case blockRules:
		return len(sum.Rules)
	case blockSources:
		return len(sum.Sources)
	}
	return len(sum.Recent)
}

func (m *tuiModel) updateOverviewKey(key string) tea.Cmd {
	sum := m.currentSummary()
	switch key {
	case "tab", "shift+tab":
		step := 1
		if key == "shift+tab" {
			step = blockCount - 1
		}
		m.block = (m.block + step) % blockCount
		return nil
	case "enter":
		selected := m.blockSelected[m.block]
		if sum == nil || selected >= m.blockLen(sum, m.block) {
			return nil
		}
		// The overview covers the whole session, so a jump starts from one condition.
		filter := tuiFilter{}
		switch m.block {
		case blockLevels:
			filter.Severity = tuiLevelOrder[selected]
		case blockRules:
			filter.Rule = sum.Rules[selected].Rule
		case blockSources:
			filter.Client = sum.Sources[selected].Client
		case blockRecent:
			drill := &tuiDrill{tab: tabOverview, view: m.alertView, selected: selected, filter: m.filter}
			m.lists[m.tab] = tuiListState{m.page, m.selected}
			m.tab, m.alertView = tabAlerts, viewList
			m.page, m.selected = 0, 0
			m.stale = true
			cmd := m.openDetail(sum.Recent[selected])
			m.drill = drill
			return cmd
		}
		return m.drillTo(filter)
	}
	tuiMove(&m.blockSelected[m.block], key, m.blockLen(sum, m.block), 5)
	return nil
}

func tuiElapsed(started time.Time) string {
	d := time.Since(started).Truncate(time.Second)
	return fmt.Sprintf("%02d:%02d:%02d", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
}

// overviewView answers how severe, which attacks, from whom, and what happened last.
func (m tuiModel) overviewView(width, height int) string {
	s := m.snapshot.Stats
	sum := m.currentSummary()
	top := "请求 " + tuiBold.Render(tuiCount(s.Transactions)) + "    告警命中 " + tuiDanger.Bold(true).Render(tuiCount(s.Alerts))
	if sum != nil {
		top += "    告警请求 " + tuiCount(uint64(sum.AlertRequests))
	}
	top += "    网络包 " + tuiCount(s.Packets)
	if s.State == "running" && !s.Started.IsZero() {
		top += "    已采集 " + tuiElapsed(s.Started)
	}
	lines := []string{termansi.Truncate(top, width, "…"), tuiMuted.Render(strings.Repeat("─", width))}
	if sum == nil {
		return strings.Join(append(lines, "正在统计告警…"), "\n")
	}
	if sum.AlertRequests == 0 {
		return strings.Join(append(lines, "当前会话没有告警命中。", tuiMuted.Render("按 2 查看全部请求，按 4 查看采集健康。")), "\n")
	}
	avail := max(1, height-len(lines))
	body, focus := []string{}, 0
	if width >= 100 {
		colWidth := (width - 3) / 2
		left := m.overviewBlock(blockLevels, sum, colWidth, len(tuiLevelOrder))
		left = append(left, "")
		left = append(left, m.overviewBlock(blockRules, sum, colWidth, max(1, avail-len(left)-1))...)
		recentRows := max(1, min(len(sum.Recent), (avail-3)/2))
		right := m.overviewBlock(blockSources, sum, colWidth, max(1, avail-recentRows-3))
		right = append(right, "")
		right = append(right, m.overviewBlock(blockRecent, sum, colWidth, recentRows)...)
		for i := 0; i < max(len(left), len(right)); i++ {
			l, r := "", ""
			if i < len(left) {
				l = left[i]
			}
			if i < len(right) {
				r = right[i]
			}
			body = append(body, tuiCell(l, colWidth)+tuiMuted.Render(" │ ")+r)
		}
	} else {
		// Stacked blocks share the height; the focused block stays in view.
		rows := max(2, (avail-4*2)/3)
		for block := 0; block < blockCount; block++ {
			if block == m.block {
				focus = len(body)
			}
			limit := rows
			if block == blockLevels {
				limit = len(tuiLevelOrder)
			}
			body = append(body, m.overviewBlock(block, sum, width, limit)...)
			body = append(body, "")
			if block == m.block {
				focus = len(body) - 1
			}
		}
	}
	start := max(0, min(focus-avail+1, len(body)-avail))
	body = body[start:min(len(body), start+avail)]
	return strings.Join(append(lines, body...), "\n")
}

// overviewBlock renders a titled block; the focused one marks its selected row.
func (m tuiModel) overviewBlock(block int, sum *tuiSummary, width, rows int) []string {
	n := m.blockLen(sum, block)
	focused := block == m.block
	title := tuiBlockNames[block]
	if block != blockLevels {
		title += fmt.Sprintf(" (%d)", n)
	}
	if block == blockSources && sum.SourcesCapped {
		title = fmt.Sprintf("%s (前 %d)", tuiBlockNames[block], tuiSourceLimit)
	}
	if focused {
		title = tuiAccent.Render("▸ " + title)
	} else {
		title = tuiBold.Render("  " + title)
	}
	lines := []string{title}
	if n == 0 {
		return append(lines, tuiMuted.Render("  暂无"))
	}
	selected := min(m.blockSelected[block], n-1)
	start := 0
	if focused {
		start = max(0, selected-rows+1)
	}
	for i := start; i < min(n, start+rows); i++ {
		row := "  " + m.overviewItem(block, i, sum, width-2)
		if focused && i == selected {
			row = tuiSelected.Render(tuiCell(termansi.Strip(row), width))
		}
		lines = append(lines, termansi.Truncate(row, width, "…"))
	}
	return lines
}

func (m tuiModel) overviewItem(block, i int, sum *tuiSummary, width int) string {
	now := time.Now()
	switch block {
	case blockLevels:
		level := tuiLevelOrder[i]
		count, most := sum.Levels[severityRank(level)], 1
		for _, c := range sum.Levels[1:] {
			most = max(most, c)
		}
		bar := ""
		if count > 0 {
			bar = strings.Repeat("█", max(1, count*max(1, width-12)/most))
		}
		style := tuiSeverityStyle(level)
		return style.Render(tuiCell(tuiSeverity(level), 4)) + tuiCell(tuiCount(uint64(count)), 8) + style.Render(bar)
	case blockRules:
		r := sum.Rules[i]
		return tuiCell(tuiLine(r.Rule), 20) + tuiSeverityStyle(r.Severity).Render(tuiCell(tuiSeverity(r.Severity), 4)) + tuiCell(tuiCount(uint64(r.Hits)), 8) + tuiMuted.Render(fmt.Sprintf("%d 个来源", r.Sources))
	case blockSources:
		src := sum.Sources[i]
		return tuiCell(tuiLine(src.Client), 18) + tuiCell(tuiCount(uint64(src.Hits)), 8) + tuiMuted.Render(tuiRuleList(src.Rules))
	}
	r := sum.Recent[i]
	return tuiMuted.Render(tuiCell(tuiShortTime(r.Time, tuiIsToday(r.Time, now)), 10)) + tuiDanger.Render(tuiCell(tuiLine(r.Rule), 14)) + tuiLine(tuiClientHost(r.Client)+"  "+r.Method+" "+r.URL)
}
func tuiRuleList(rules []string) string {
	switch len(rules) {
	case 0:
		return ""
	case 1:
		return tuiLine(rules[0])
	}
	return fmt.Sprintf("%s 等 %d 条规则", tuiLine(rules[0]), len(rules))
}

// alertsView puts the view switcher above the rule, source or record list.
func (m tuiModel) alertsView(width, height int) string {
	names := [alertViewCount]string{"按规则", "按来源", "逐条"}
	parts := []string{}
	for i, name := range names {
		if i == m.alertView {
			parts = append(parts, tuiAccent.Render("["+name+"]"))
		} else {
			parts = append(parts, tuiMuted.Render(" "+name+" "))
		}
	}
	selector := tuiSpread(tuiMuted.Render("视图 ")+strings.Join(parts, " "), tuiMuted.Render("v 切换视图"), width)
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
		lines = append(lines, termansi.Truncate(row, width, "…"))
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
