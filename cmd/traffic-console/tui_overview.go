package main

// The overview page mirrors the web overview: metric tiles, the request and
// alert timeline, rule, source, severity and status breakdowns, the latest
// alerts and the capture state. Every block is focusable with Tab and Enter
// opens the matching requests, as a click does on the web page.

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

const (
	blockTimeline = iota
	blockRules
	blockClients
	blockLevels
	blockStatus
	blockRecent
	blockCount
)

var tuiBlockNames = [blockCount]string{"请求与告警时间线", "命中规则", "来源地址", "告警级别", "响应状态", "最近告警"}
var tuiLevelOrder = []string{"high", "medium", "low"}
var tuiStatusOrder = []string{"2xx", "3xx", "4xx", "5xx", "1xx", "pending", "other"}

var tuiBar = lipgloss.NewStyle().Foreground(lipgloss.Color("#4AA8A8"))

// tuiOverview is what the overview needs beyond the session status.
type tuiOverview struct {
	Summary  sessionSummary
	Timeline sessionTimeline
	Recent   []tuiRow
}

func loadTUIOverview(ctx context.Context, s *Store) (*tuiOverview, error) {
	fresh, err := openStore(s.dir)
	if err != nil {
		return nil, err
	}
	defer fresh.db.Close()
	result := &tuiOverview{}
	if result.Summary, err = querySessionSummary(ctx, fresh.db, tuiFilter{}); err != nil {
		return nil, err
	}
	if result.Timeline, err = querySessionTimeline(ctx, fresh.db, tuiFilter{}, false); err != nil {
		return nil, err
	}
	recent, err := loadTUISnapshot(ctx, fresh, tuiFilter{}, true, 0, "", nil, 8)
	if err != nil {
		return nil, err
	}
	result.Recent = recent.Rows
	return result, nil
}

func loadTUITimeline(ctx context.Context, s *Store, filter tuiFilter, alertsOnly bool) (*sessionTimeline, error) {
	fresh, err := openStore(s.dir)
	if err != nil {
		return nil, err
	}
	defer fresh.db.Close()
	timeline, err := querySessionTimeline(ctx, fresh.db, filter, alertsOnly)
	return &timeline, err
}

// tuiOrdered keeps the named counts in display order and drops empty ones.
func tuiOrdered(items []webCount, order []string) []webCount {
	result := []webCount{}
	for _, name := range order {
		for _, item := range items {
			if item.Name == name && item.Count > 0 {
				result = append(result, item)
			}
		}
	}
	return result
}

func (m tuiModel) blockLen(block int) int {
	o := m.overview
	if o == nil {
		return 0
	}
	switch block {
	case blockTimeline:
		return len(m.timelineColumns(&o.Timeline, m.timelinePlot()))
	case blockRules:
		return len(o.Summary.Rules)
	case blockClients:
		return len(o.Summary.Clients)
	case blockLevels:
		return len(tuiOrdered(o.Summary.Severities, tuiLevelOrder))
	case blockStatus:
		return len(tuiOrdered(o.Summary.Statuses, tuiStatusOrder))
	}
	return len(o.Recent)
}

// drillTo opens a list with one condition and remembers how to come back.
func (m *tuiModel) drillTo(tab int, filter tuiFilter) tea.Cmd {
	drill := &tuiDrill{tab: m.tab, view: m.alertView, filter: m.filter}
	if m.tab == tabOverview {
		drill.selected = m.blockSelected[m.block]
	} else {
		drill.selected = m.aggSelected[m.alertView]
	}
	m.lists[m.tab] = tuiListState{m.page, m.selected}
	m.tab = tab
	if tab == tabAlerts {
		m.alertView = viewList
	}
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

func (m *tuiModel) updateOverviewKey(key string) tea.Cmd {
	o := m.overview
	switch key {
	case "tab", "shift+tab":
		step := 1
		if key == "shift+tab" {
			step = blockCount - 1
		}
		m.block = (m.block + step) % blockCount
		m.timelineAnchor = 0
		return nil
	case "enter":
		selected := m.blockSelected[m.block]
		if o == nil || selected >= m.blockLen(m.block) {
			return nil
		}
		// The overview covers the whole session, so a jump starts from one condition.
		switch m.block {
		case blockTimeline:
			since, until := m.timelineSelection(&o.Timeline)
			m.timelineAnchor = 0
			return m.drillTo(tabRequests, tuiFilter{Since: since, Until: until, UntilExclusive: true})
		case blockRules:
			return m.drillTo(tabAlerts, tuiFilter{Rule: o.Summary.Rules[selected].Name})
		case blockClients:
			client := strings.TrimSuffix(strings.TrimPrefix(o.Summary.Clients[selected].Name, "["), "]")
			return m.drillTo(tabRequests, tuiFilter{Client: client})
		case blockLevels:
			return m.drillTo(tabAlerts, tuiFilter{Severity: tuiOrdered(o.Summary.Severities, tuiLevelOrder)[selected].Name})
		case blockStatus:
			name := tuiOrdered(o.Summary.Statuses, tuiStatusOrder)[selected].Name
			filter := tuiFilter{}
			if name != "other" && name != "1xx" {
				filter.Status = name
			}
			return m.drillTo(tabRequests, filter)
		case blockRecent:
			drill := &tuiDrill{tab: tabOverview, view: m.alertView, selected: selected, filter: m.filter}
			m.lists[m.tab] = tuiListState{m.page, m.selected}
			m.tab, m.alertView = tabAlerts, viewList
			m.filter = tuiFilter{}
			m.page, m.selected = 0, 0
			m.stale = true
			cmd := m.openDetail(o.Recent[selected])
			m.drill = drill
			return cmd
		}
	}
	if m.block == blockTimeline {
		m.moveTimeline(key, m.blockLen(blockTimeline))
		return nil
	}
	tuiMove(&m.blockSelected[m.block], key, m.blockLen(m.block), 5)
	return nil
}

func tuiDuration(seconds int) string {
	switch {
	case seconds < 60:
		return fmt.Sprintf("%d 秒", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%d 分钟", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%d 小时", seconds/3600)
	}
	return fmt.Sprintf("%d 天", seconds/86400)
}

func tuiRelative(t time.Time) string {
	seconds := max(0, time.Since(t).Seconds())
	switch {
	case seconds < 60:
		return "刚刚"
	case seconds < 3600:
		return fmt.Sprintf("%d 分钟前", int(seconds/60))
	case seconds < 86400:
		return fmt.Sprintf("%d 小时前", int(seconds/3600))
	}
	return fmt.Sprintf("%d 天前", int(seconds/86400))
}

func tuiElapsed(started time.Time) string {
	d := time.Since(started).Truncate(time.Second)
	return fmt.Sprintf("%02d:%02d:%02d", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
}

// overviewTiles renders the six web tiles in one or two rows.
func (m tuiModel) overviewTiles(width int) []string {
	s := m.snapshot.Stats
	o := m.overview
	type tile struct {
		label string
		value uint64
		note  string
		style lipgloss.Style
	}
	warn := func(n uint64) lipgloss.Style {
		if n > 0 {
			return tuiWarn.Bold(true)
		}
		return tuiBold
	}
	tiles := []tile{
		{"累计请求", s.Transactions, "", tuiBold},
		{"累计告警命中", s.Alerts, "", tuiBold},
		{"网络包", s.Packets, "", tuiBold},
		{"网卡丢包", s.Dropped, "", warn(s.Dropped)},
		{"用户态队列丢弃", s.QueueDropped, "", warn(s.QueueDropped)},
		{"TLS 已知丢弃", s.TLSDropped, "已观测下限", warn(s.TLSDropped)},
	}
	if o != nil {
		tiles[0].note = "索引内 " + tuiCount(uint64(o.Summary.Total))
		tiles[1].note = "涉及 " + tuiCount(uint64(o.Summary.Alerted)) + " 条请求"
	}
	if s.Alerts > 0 {
		tiles[1].style = tuiDanger.Bold(true)
	}
	if s.TLSWireRecords > 0 {
		tiles[2].note = "TLS 外层 " + tuiCount(s.TLSWireRecords)
	}
	perRow := 6
	if width < 96 {
		perRow = 3
	}
	cell := width / perRow
	lines := []string{}
	for start := 0; start < len(tiles); start += perRow {
		labels, values := "", ""
		for _, t := range tiles[start:min(len(tiles), start+perRow)] {
			labels += tuiMuted.Render(tuiCell(t.label, cell))
			value := t.style.Render(tuiCount(t.value))
			if t.note != "" {
				value += " " + tuiMuted.Render(t.note)
			}
			values += tuiCell(value, cell)
		}
		lines = append(lines, labels, values)
	}
	return lines
}

// overviewView lays the blocks out like the web page and scrolls to keep the
// focused block in view on short terminals.
func (m tuiModel) overviewView(width, height int) string {
	o := m.overview
	lines := m.overviewTiles(width)
	if s := m.snapshot.Stats; s.State == "running" && !s.Started.IsZero() {
		lines = append(lines, tuiMuted.Render("已采集 "+tuiElapsed(s.Started)))
	}
	lines = append(lines, "")
	if o == nil {
		return strings.Join(append(lines, "正在统计…"), "\n")
	}
	focusStart, focusEnd := 0, 0
	addBlock := func(blocks []int, section []string) {
		for _, b := range blocks {
			if b == m.block {
				focusStart, focusEnd = len(lines), len(lines)+len(section)
			}
		}
		lines = append(lines, section...)
		lines = append(lines, "")
	}
	addBlock([]int{blockTimeline}, m.timelineBlock(width, max(3, min(7, (height-12)/4))))
	columns := func(width int, blocks ...[]string) []string {
		n := len(blocks)
		colWidth := (width - 3*(n-1)) / n
		rows := 0
		for _, b := range blocks {
			rows = max(rows, len(b))
		}
		result := make([]string, rows)
		for i := range result {
			parts := []string{}
			for _, b := range blocks {
				cell := ""
				if i < len(b) {
					cell = b[i]
				}
				parts = append(parts, tuiCell(cell, colWidth))
			}
			result[i] = strings.Join(parts, tuiMuted.Render(" │ "))
		}
		return result
	}
	switch {
	case width >= 120:
		col := (width - 6) / 3
		addBlock([]int{blockRules, blockClients, blockLevels, blockStatus}, columns(width, m.barBlock(blockRules, col), m.barBlock(blockClients, col), append(append(m.stackBlock(blockLevels, col), ""), m.stackBlock(blockStatus, col)...)))
		col = (width - 3) / 2
		addBlock([]int{blockRecent}, columns(width, m.recentBlock(col), m.factsBlock(col)))
	case width >= 80:
		col := (width - 3) / 2
		addBlock([]int{blockRules, blockClients}, columns(width, m.barBlock(blockRules, col), m.barBlock(blockClients, col)))
		addBlock([]int{blockLevels, blockStatus}, columns(width, m.stackBlock(blockLevels, col), m.stackBlock(blockStatus, col)))
		addBlock([]int{blockRecent}, m.recentBlock(width))
		addBlock(nil, m.factsBlock(width))
	default:
		addBlock([]int{blockRules}, m.barBlock(blockRules, width))
		addBlock([]int{blockClients}, m.barBlock(blockClients, width))
		addBlock([]int{blockLevels}, m.stackBlock(blockLevels, width))
		addBlock([]int{blockStatus}, m.stackBlock(blockStatus, width))
		addBlock([]int{blockRecent}, m.recentBlock(width))
		addBlock(nil, m.factsBlock(width))
	}
	start := 0
	if focusEnd > height {
		start = min(focusStart, focusEnd-height)
	}
	start = max(0, min(start, len(lines)-height))
	lines = lines[start:min(len(lines), start+height)]
	for i, line := range lines {
		lines[i] = termansi.Truncate(line, width, "…")
	}
	return strings.Join(lines, "\n")
}

func (m tuiModel) blockTitle(block int, extra string) string {
	title := tuiBlockNames[block]
	if block == m.block {
		title = tuiAccent.Render("▸ " + title)
	} else {
		title = tuiBold.Render("  " + title)
	}
	title = tuiHit(fmt.Sprintf("block:%d", block), title)
	if extra != "" {
		title += "  " + tuiMuted.Render(extra)
	}
	return title
}

// barBlock is a web bar list: label, proportional bar and count.
func (m tuiModel) barBlock(block, width int) []string {
	o := m.overview
	items := o.Summary.Rules
	hint, empty := "按请求数", "没有规则命中"
	if block == blockClients {
		items, hint, empty = o.Summary.Clients, "告警优先", "暂无请求"
	}
	lines := []string{m.blockTitle(block, hint)}
	if len(items) == 0 {
		return append(lines, tuiMuted.Render("  "+empty))
	}
	peak := 1
	for _, item := range items {
		peak = max(peak, item.Count)
	}
	selected := min(m.blockSelected[block], len(items)-1)
	labelWidth := max(8, min(24, width*2/5))
	for i, item := range items {
		count := ""
		if block == blockRules {
			count = tuiSeverityStyle(item.Severity).Render(tuiSeverity(item.Severity)) + " " + tuiCount(uint64(item.Count))
		} else {
			count = tuiCount(uint64(item.Count)) + " 请求"
			if item.Alerts > 0 {
				count = tuiDanger.Render(tuiCount(uint64(item.Alerts))+" 告警") + " · " + count
			}
		}
		barWidth := max(1, width-2-labelWidth-lipgloss.Width(count)-2)
		bar := strings.Repeat("█", max(1, item.Count*barWidth/peak))
		style := tuiBar
		if block == blockRules {
			style = tuiSeverityStyle(item.Severity)
		} else if item.Alerts > 0 {
			style = tuiDanger
		}
		row := "  " + tuiCell(tuiLine(item.Name), labelWidth) + style.Render(tuiCell(bar, barWidth)) + "  " + count
		if block == m.block && i == selected {
			row = tuiSelected.Render(tuiCell(termansi.Strip(row), width))
		}
		lines = append(lines, tuiHit(fmt.Sprintf("ov:%d:%d", block, i), tuiCell(row, width)))
	}
	return lines
}

// stackBlock is a web stack bar: one proportional bar and a selectable legend.
func (m tuiModel) stackBlock(block, width int) []string {
	o := m.overview
	if block == blockStatus && o.Summary.Statuses == nil {
		return []string{m.blockTitle(block, ""), tuiMuted.Render("  索引较大，已跳过状态统计。可在请求列表按状态筛选。")}
	}
	items := tuiOrdered(o.Summary.Severities, tuiLevelOrder)
	label := func(name string) string { return tuiSeverity(name) + "危" }
	style := tuiSeverityStyle
	empty := "没有告警"
	if block == blockStatus {
		items, empty = tuiOrdered(o.Summary.Statuses, tuiStatusOrder), "暂无请求"
		label = func(name string) string {
			switch name {
			case "pending":
				return "待响应"
			case "other":
				return "其他"
			}
			return name
		}
		style = func(name string) lipgloss.Style {
			switch name {
			case "2xx":
				return tuiGood
			case "4xx":
				return tuiWarn
			case "5xx":
				return tuiDanger
			case "pending", "other":
				return tuiMuted
			}
			return tuiBar
		}
	}
	lines := []string{m.blockTitle(block, "")}
	total := 0
	for _, item := range items {
		total += item.Count
	}
	if total == 0 {
		return append(lines, tuiMuted.Render("  "+empty))
	}
	barWidth := max(1, width-2)
	var bar strings.Builder
	used := 0
	for i, item := range items {
		n := item.Count * barWidth / total
		if i == len(items)-1 {
			n = barWidth - used
		}
		n = max(1, n)
		used += n
		bar.WriteString(style(item.Name).Render(strings.Repeat("█", n)))
	}
	lines = append(lines, "  "+termansi.Truncate(bar.String(), barWidth, ""))
	selected := min(m.blockSelected[block], len(items)-1)
	for i, item := range items {
		row := "  " + style(item.Name).Render("■ "+tuiCell(label(item.Name), 8)) + tuiCell(tuiCount(uint64(item.Count)), 10) + tuiMuted.Render(fmt.Sprintf("%d%%", (item.Count*100+total/2)/total))
		if block == m.block && i == selected {
			row = tuiSelected.Render(tuiCell(termansi.Strip(row), width))
		}
		lines = append(lines, tuiHit(fmt.Sprintf("ov:%d:%d", block, i), tuiCell(row, width)))
	}
	return lines
}

func (m tuiModel) recentBlock(width int) []string {
	o := m.overview
	lines := []string{m.blockTitle(blockRecent, "Enter 打开详情 · ") + tuiMuted.Render(tuiHints("3 查看全部"))}
	if len(o.Recent) == 0 {
		return append(lines, tuiMuted.Render("  没有告警。规则命中的请求会出现在这里。"))
	}
	selected := min(m.blockSelected[blockRecent], len(o.Recent)-1)
	for i, r := range o.Recent {
		at, _ := time.Parse(time.RFC3339Nano, r.Time)
		row := "  " + tuiSeverityStyle(r.Severity).Render(tuiCell(tuiSeverity(r.Severity), 3)) + tuiMuted.Render(tuiCell(tuiFormatTime(at, "clock"), 10)) + tuiCell(tuiLine(tuiClientHost(r.Client)), 18) + tuiLine(r.Method+" "+r.URL)
		if m.block == blockRecent && i == selected {
			row = tuiSelected.Render(tuiCell(termansi.Strip(row), width))
		}
		lines = append(lines, tuiHit(fmt.Sprintf("ov:%d:%d", blockRecent, i), tuiCell(row, width)))
	}
	return lines
}

// factsBlock condenses the web "采集状态" card; page 4 has every detail.
func (m tuiModel) factsBlock(width int) []string {
	s := m.snapshot.Stats
	label := func(s string) string { return "  " + tuiMuted.Render(tuiCell(s, 10)) }
	started := "未知"
	if !s.Started.IsZero() {
		started = tuiFormatTime(s.Started, "") + "（" + tuiRelative(s.Started) + "）"
	}
	stopped := "—"
	if !s.Stopped.IsZero() {
		stopped = tuiFormatTime(s.Stopped, "")
	}
	if s.StopReason != "" {
		stopped += " · " + tuiLine(s.StopReason)
	}
	last := "—"
	if !s.LastPacketAt.IsZero() {
		last = tuiIn(s.LastPacketAt).Format("2006-01-02 15:04:05.000")
	}
	drain := s.DrainState
	if drain == "" {
		drain = "未知"
	}
	probes := []string{}
	for _, t := range s.Targets {
		probes = append(probes, tuiTargetStyle(t.State).Render(tuiLine(t.Service)+" "+tuiLine(t.State)))
	}
	if len(probes) == 0 {
		probes = append(probes, tuiMuted.Render("没有服务探针记录"))
	}
	errors := tuiMuted.Render("没有记录到错误")
	if len(s.Errors) > 0 {
		errors = tuiDanger.Render(fmt.Sprintf("%d 条", len(s.Errors)))
	}
	lines := []string{tuiBold.Render("  采集状态") + "  " + tuiHit("tab:3", tuiMuted.Render("按 4 查看全部"))}
	for _, row := range [][2]string{{"状态", tuiStateBadge(s.State)}, {"开始时间", started}, {"停止时间", stopped}, {"最后收包", last}, {"数据排空", tuiLine(drain)}, {"服务探针", strings.Join(probes, tuiMuted.Render(" · "))}, {"采集错误", errors}} {
		lines = append(lines, termansi.Truncate(label(row[0])+row[1], width, "…"))
	}
	return lines
}

// overviewBrief describes a clicked overview row in one line; a double click
// or Enter opens it.
func (m tuiModel) overviewBrief(block, i int) string {
	o := m.overview
	if o == nil || i >= m.blockLen(block) {
		return ""
	}
	percent := func(n int, items []webCount) string {
		total := 0
		for _, item := range items {
			total += item.Count
		}
		return fmt.Sprintf("%s 条（%d%%）", tuiCount(uint64(n)), (n*100+total/2)/max(1, total))
	}
	switch block {
	case blockRules:
		r := o.Summary.Rules[i]
		return fmt.Sprintf("规则 %s · %s危 · 命中 %s 条请求 · 再点一次查看这些告警", tuiLine(r.Name), tuiSeverity(r.Severity), tuiCount(uint64(r.Count)))
	case blockClients:
		c := o.Summary.Clients[i]
		text := fmt.Sprintf("来源 %s · %s 请求", tuiLine(c.Name), tuiCount(uint64(c.Count)))
		if c.Alerts > 0 {
			text += fmt.Sprintf(" · %s 告警", tuiCount(uint64(c.Alerts)))
		}
		return text + " · 再点一次查看这个来源的请求"
	case blockLevels:
		items := tuiOrdered(o.Summary.Severities, tuiLevelOrder)
		return fmt.Sprintf("%s危告警 %s · 再点一次查看这一级别及以上的告警", tuiSeverity(items[i].Name), percent(items[i].Count, items))
	case blockStatus:
		items := tuiOrdered(o.Summary.Statuses, tuiStatusOrder)
		name := map[string]string{"pending": "待响应", "other": "其他状态"}[items[i].Name]
		if name == "" {
			name = "响应 " + items[i].Name
		}
		return fmt.Sprintf("%s · %s · 再点一次查看这些请求", name, percent(items[i].Count, items))
	case blockRecent:
		r := o.Recent[i]
		at, _ := time.Parse(time.RFC3339Nano, r.Time)
		return fmt.Sprintf("%s危 %s · %s · %s %s · %s · 再点一次打开详情", tuiSeverity(r.Severity), tuiLine(r.Rule), tuiFormatTime(at, "clock"), tuiLine(tuiClientHost(r.Client)), tuiLine(r.Method), tuiLine(r.URL))
	}
	return ""
}
