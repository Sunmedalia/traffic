package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	termansi "github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/traffic/internal/session"
)

const (
	tabOverview = iota
	tabRequests
	tabAlerts
	tabHealth
	tuiTabCount
)

// Frame rows outside the content area: identity, tabs, filters, notice, keys.
const tuiChrome = 5

type tuiTick time.Time
type tuiLoaded struct {
	Version  uint64
	Snapshot tuiSnapshot
	Err      error
}
type tuiExported struct {
	ID, Path string
	Size     int64
	Err      error
}

type tuiListState struct{ page, selected int }

type tuiModel struct {
	ctx                                  context.Context
	store                                *Store
	refresh                              time.Duration
	filter                               tuiFilter
	snapshot                             tuiSnapshot
	title                                string
	width, height, tab, page, selected   int
	detailTab                            int
	lists                                [tuiTabCount]tuiListState
	version                              uint64
	busy, pending, paused, details, help bool
	stale, pickDetail                    bool
	detailID, errorText, flash           string
	form                                 *tuiForm
	export                               *tuiExport
	viewport                             viewport.Model
}

var tuiAccent = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#5FD7D7"))
var tuiMuted = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
var tuiSelected = lipgloss.NewStyle().Reverse(true)
var tuiDanger = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF7777"))
var tuiWarn = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6C35C"))
var tuiGood = lipgloss.NewStyle().Foreground(lipgloss.Color("#7BD88F"))
var tuiBold = lipgloss.NewStyle().Bold(true)

func (m tuiModel) tick() tea.Cmd {
	return tea.Tick(m.refresh, func(t time.Time) tea.Msg { return tuiTick(t) })
}
func (m tuiModel) Init() tea.Cmd { return m.tick() }

// following means new records enter at the top and the cursor stays on the newest.
func (m tuiModel) following() bool { return m.page == 0 && m.selected == 0 && !m.details }
func (m tuiModel) listTab() bool   { return m.tab == tabRequests || m.tab == tabAlerts }
func (m tuiModel) modal() bool     { return m.form != nil || m.export != nil }

func (m *tuiModel) load() tea.Cmd {
	if m.busy {
		m.pending = true
		return nil
	}
	m.busy = true
	m.pending = false
	version, filter, page, alertsOnly, detailID := m.version, m.filter, m.page, m.tab == tabAlerts, m.detailID
	var anchor *tuiRow
	// Once the cursor leaves the newest row, anchor the page so rows stop moving.
	if !m.following() && !m.stale && m.snapshot.Page == page && len(m.snapshot.Rows) > 0 {
		row := m.snapshot.Rows[0]
		anchor = &row
	}
	rootCtx, store := m.ctx, m.store
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(rootCtx, 3*time.Second)
		defer cancel()
		snapshot, err := loadTUISnapshot(ctx, store, filter, alertsOnly, page, detailID, anchor)
		return tuiLoaded{version, snapshot, err}
	}
}
func (m *tuiModel) changed() tea.Cmd  { m.version++; return m.load() }
func (m tuiModel) contentHeight() int { return max(1, m.height-tuiChrome) }
func (m tuiModel) split() bool        { return m.details && m.width >= 120 }
func (m *tuiModel) resize() {
	width := max(1, m.width)
	if m.split() {
		width = max(1, m.width-m.width/2-3)
	}
	m.viewport.SetWidth(width)
	m.viewport.SetHeight(m.contentHeight())
	m.updateContent()
}
func (m *tuiModel) updateContent() {
	content := ""
	switch {
	case m.details:
		content = m.detailContent()
	case m.tab == tabHealth:
		content = m.healthContent()
	default:
		content = m.overview()
	}
	m.viewport.SetContent(termansi.Hardwrap(content, max(1, m.viewport.Width()), true))
}

// switchTab keeps each list tab's own page and cursor.
func (m *tuiModel) switchTab(tab int) tea.Cmd {
	if tab == m.tab && !m.details {
		return nil
	}
	m.lists[m.tab] = tuiListState{m.page, m.selected}
	m.tab = tab
	m.page, m.selected = m.lists[tab].page, m.lists[tab].selected
	m.closeDetail()
	m.stale = true
	m.viewport.GotoTop()
	m.resize()
	return m.changed()
}
func (m *tuiModel) closeDetail() {
	m.details = false
	m.detailID = ""
	m.pickDetail = false
	m.snapshot.Detail = nil
	m.snapshot.DetailMissing = false
}
func (m *tuiModel) applyFilter(filter tuiFilter) tea.Cmd {
	m.filter = filter
	m.page, m.selected = 0, 0
	m.lists = [tuiTabCount]tuiListState{}
	m.closeDetail()
	m.stale = true
	m.resize()
	return m.changed()
}
func (m *tuiModel) openDetail(row tuiRow) tea.Cmd {
	m.details = true
	m.detailID = row.ID
	m.snapshot.Detail = nil
	m.snapshot.DetailMissing = false
	m.detailTab = 0
	if row.Severity != "" {
		m.detailTab = 3
	}
	m.viewport.GotoTop()
	m.resize()
	return m.changed()
}

// stepDetail opens the neighbouring record, crossing page boundaries.
func (m *tuiModel) stepDetail(step int) tea.Cmd {
	next := m.selected + step
	switch {
	case next >= 0 && next < len(m.snapshot.Rows):
		m.selected = next
		return m.openDetail(m.snapshot.Rows[next])
	case next >= len(m.snapshot.Rows) && (m.page+1)*100 < m.snapshot.Count:
		m.page, m.selected = m.page+1, 0
	case next < 0 && m.page > 0:
		m.page, m.selected = m.page-1, 99
	default:
		m.flash = "已经是第一条或最后一条"
		return nil
	}
	m.pickDetail = true
	return m.changed()
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		return m, nil
	case tuiTick:
		var load tea.Cmd
		if !m.paused {
			load = m.load()
		}
		return m, tea.Batch(m.tick(), load)
	case tuiLoaded:
		m.busy = false
		if msg.Version == m.version {
			if msg.Err != nil {
				m.errorText = cleanTUIText(msg.Err.Error())
			} else {
				m.applySnapshot(msg.Snapshot)
				if m.pickDetail && len(m.snapshot.Rows) > 0 {
					m.pickDetail = false
					return m, m.openDetail(m.snapshot.Rows[m.selected])
				}
			}
		}
		if m.pending || msg.Version != m.version {
			return m, m.load()
		}
		return m, nil
	case tuiExported:
		if m.export != nil && m.export.id == msg.ID {
			m.export.running = false
			if msg.Err != nil {
				m.export.err = tuiExportError(msg.Err)
				return m, nil
			}
			m.export = nil
		}
		if msg.Err == nil {
			m.flash = fmt.Sprintf("已导出 %s · %s", msg.Path, tuiBytes(msg.Size))
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	}
	if m.form != nil {
		return m, m.form.update(msg)
	}
	if m.export != nil {
		var cmd tea.Cmd
		m.export.input, cmd = m.export.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *tuiModel) applySnapshot(snapshot tuiSnapshot) {
	wasFollowing := m.following()
	selectedID := ""
	if !m.stale && len(m.snapshot.Rows) > m.selected {
		selectedID = m.snapshot.Rows[m.selected].ID
	}
	m.snapshot, m.page, m.stale = snapshot, snapshot.Page, false
	m.selected = min(m.selected, max(0, len(m.snapshot.Rows)-1))
	if !wasFollowing && !m.pickDetail {
		for i, row := range m.snapshot.Rows {
			if row.ID == selectedID {
				m.selected = i
				break
			}
		}
	}
	m.errorText = ""
	m.updateContent()
}

func (m *tuiModel) updateKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		return m, tea.Quit
	}
	if m.form != nil {
		return m, m.updateForm(msg)
	}
	if m.export != nil {
		return m, m.updateExport(msg)
	}
	m.flash = ""
	if key == "q" {
		return m, tea.Quit
	}
	if m.help {
		if key == "?" || key == "esc" {
			m.help = false
		}
		return m, nil
	}
	switch key {
	case "?":
		m.help = true
		return m, nil
	case "/":
		m.form = newTUIForm(m.filter, m.services(), m.width)
		return m, m.form.focus()
	case " ", "space":
		m.paused = !m.paused
		if !m.paused {
			return m, m.load()
		}
		return m, nil
	case "r":
		return m, m.load()
	case "1", "2", "3", "4":
		return m, m.switchTab(int(key[0] - '1'))
	case "x":
		if m.filter != (tuiFilter{}) {
			return m, m.applyFilter(tuiFilter{})
		}
		return m, nil
	case "esc":
		if m.details {
			m.closeDetail()
			m.viewport.GotoTop()
			m.resize()
			return m, m.changed()
		}
		return m, nil
	}
	if m.details || m.listTab() {
		switch key {
		case "c", "m", "H":
			return m, m.toggleFromRow(key)
		case "e":
			return m, m.openExport()
		}
	}
	if m.details {
		switch key {
		case "tab", "shift+tab":
			step := 1
			if key == "shift+tab" {
				step = 3
			}
			m.detailTab = (m.detailTab + step) % 4
			m.viewport.GotoTop()
			m.updateContent()
			return m, nil
		case "J":
			return m, m.stepDetail(1)
		case "K":
			return m, m.stepDetail(-1)
		}
	}
	if m.details || !m.listTab() {
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}
	switch key {
	case "up", "k":
		m.selected = max(0, m.selected-1)
	case "down", "j":
		m.selected = min(max(0, len(m.snapshot.Rows)-1), m.selected+1)
	case "home", "g":
		// Back to the newest record, which resumes following.
		pageChanged := m.page != 0
		m.page, m.selected = 0, 0
		if pageChanged || m.snapshot.Newer > 0 {
			return m, m.changed()
		}
	case "end", "G":
		m.selected = max(0, len(m.snapshot.Rows)-1)
	case "pgdown", "right", "n":
		if (m.page+1)*100 < m.snapshot.Count {
			m.page++
			m.selected = 0
			return m, m.changed()
		}
	case "pgup", "left", "p":
		if m.page > 0 {
			m.page--
			m.selected = 0
			return m, m.changed()
		}
	case "enter":
		if len(m.snapshot.Rows) > m.selected {
			return m, m.openDetail(m.snapshot.Rows[m.selected])
		}
	}
	return m, nil
}

// currentRow is the record a row action applies to: the open detail or the cursor.
func (m tuiModel) currentRow() (tuiRow, bool) {
	if m.details && m.snapshot.Detail != nil && m.snapshot.Detail.ID == m.detailID {
		t := m.snapshot.Detail
		row := tuiRow{ID: t.ID, Client: t.Client, Host: t.Host, URL: t.URL, Method: t.Method}
		best := 0
		for _, a := range t.Alerts {
			if rank := severityRank(a.Severity); rank > best || row.Rule == "" {
				best, row.Rule, row.Severity = max(best, rank), a.Rule, a.Severity
			}
		}
		return row, true
	}
	if !m.stale && m.selected < len(m.snapshot.Rows) {
		return m.snapshot.Rows[m.selected], true
	}
	return tuiRow{}, false
}

// toggleFromRow filters by the client, rule or Host of the current record.
func (m *tuiModel) toggleFromRow(key string) tea.Cmd {
	row, ok := m.currentRow()
	if !ok {
		m.flash = "没有选中的请求"
		return nil
	}
	filter := m.filter
	toggle := func(field *string, value, empty string) bool {
		if value == "" {
			m.flash = empty
			return false
		}
		if *field == value {
			*field = ""
		} else {
			*field = value
		}
		return true
	}
	applied := false
	switch key {
	case "c":
		applied = toggle(&filter.Client, tuiClientHost(row.Client), "该请求没有客户端地址")
	case "m":
		applied = toggle(&filter.Rule, row.Rule, "该请求没有命中规则")
	case "H":
		applied = toggle(&filter.Keyword, row.Host, "该请求没有 Host")
	}
	if !applied {
		return nil
	}
	if !m.listTab() {
		m.tab = tabRequests
	}
	return m.applyFilter(filter)
}

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
		return t.Local().Format("01-02 15:04:05")
	}
	return tuiLine(s)
}

// tuiShortTime drops the date for records from today.
func tuiShortTime(s string, today bool) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil && today {
		return t.Local().Format("15:04:05")
	}
	return tuiTime(s)
}
func tuiIsToday(s string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return false
	}
	y1, m1, d1 := t.Local().Date()
	y2, m2, d2 := now.Local().Date()
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

// tuiSpread places right-aligned text at the end of a line, dropping it when there is no room.
func tuiSpread(left, right string, width int) string {
	lw, rw := lipgloss.Width(left), lipgloss.Width(right)
	if lw+rw+2 > width {
		return termansi.Truncate(left, width, "…")
	}
	return left + strings.Repeat(" ", width-lw-rw) + right
}

// tuiHealth rates capture trust: 0 normal, 1 needs a look, 2 capture is not working.
func (m tuiModel) tuiHealth() (int, []string) {
	s := m.snapshot.Stats
	level, reasons := 0, []string{}
	warn := func(l int, reason string) {
		level = max(level, l)
		reasons = append(reasons, reason)
	}
	switch s.State {
	case "failed":
		warn(2, "采集失败")
	case "stale":
		warn(2, "采集心跳过期")
	}
	if m.snapshot.StatusWarning != "" && s.State != "stale" {
		warn(1, m.snapshot.StatusWarning)
	}
	counters := []struct {
		n     uint64
		label string
	}{{s.Dropped, "网卡丢包"}, {s.QueueDropped, "队列丢弃"}, {s.TLSDropped, "TLS 已知丢弃"}, {s.AlertDeliveryFailed, "推送失败"}, {s.AlertDeliveryDropped, "推送队列丢弃"}}
	for _, c := range counters {
		if c.n > 0 {
			warn(1, fmt.Sprintf("%s %s", c.label, tuiCount(c.n)))
		}
	}
	for _, target := range s.Targets {
		if tuiTargetProblem(target.State) {
			warn(1, fmt.Sprintf("%s 探针 %s", tuiLine(target.Service), tuiLine(target.State)))
		}
	}
	if len(s.Errors) > 0 {
		warn(1, fmt.Sprintf("采集错误 %d 条", len(s.Errors)))
	}
	return level, reasons
}
func tuiTargetProblem(state string) bool {
	switch state {
	case "java-probe-required", "https-unverified", "unavailable", "partial", "failed":
		return true
	}
	return false
}
func tuiTargetStyle(state string) lipgloss.Style {
	if tuiTargetProblem(state) {
		return tuiWarn
	}
	if state == "attached" || state == "active-preload" || state == "listening-preload" {
		return tuiGood
	}
	return lipgloss.NewStyle()
}

func (m tuiModel) startedText() string {
	s := m.snapshot.Stats
	if s.Started.IsZero() {
		return "未知"
	}
	return s.Started.Local().Format("2006-01-02 15:04:05 MST -07:00")
}
func (m tuiModel) overview() string {
	s := m.snapshot.Stats
	elapsed := ""
	if s.State == "running" && !s.Started.IsZero() {
		d := time.Since(s.Started).Truncate(time.Second)
		elapsed = fmt.Sprintf("    已采集 %02d:%02d:%02d", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
	}
	lines := []string{
		tuiAccent.Render("采集概览"), "",
		fmt.Sprintf("累计请求  %s    累计告警命中  %s    网络包  %s", tuiBold.Render(tuiCount(s.Transactions)), tuiDanger.Bold(true).Render(tuiCount(s.Alerts)), tuiCount(s.Packets)), "",
		"会话  " + tuiLine(m.store.dir),
		"状态  " + tuiStateBadge(s.State) + elapsed,
		"开始  " + m.startedText(),
	}
	if s.TLS != "" {
		lines = append(lines, "TLS   "+tuiLine(s.TLS))
	}
	lines = append(lines, "")
	if len(s.Targets) > 0 {
		names := []string{}
		for _, target := range s.Targets {
			names = append(names, fmt.Sprintf("%s · PID %d", tuiLine(target.Service), target.PID))
		}
		lines = append(lines, "服务  "+strings.Join(names, "    "), "")
	}
	level, reasons := m.tuiHealth()
	lines = append(lines, tuiAccent.Render("采集可信度"))
	switch level {
	case 0:
		lines = append(lines, "未发现丢弃、探针异常或采集错误。完整性仍未验证，按 4 查看详情。")
	case 1:
		lines = append(lines, tuiWarn.Render("需要关注："+strings.Join(reasons, "，")), "按 4 查看详情。")
	default:
		lines = append(lines, tuiDanger.Render("采集异常："+strings.Join(reasons, "，")), "已保存的请求仍可浏览，按 4 查看详情。")
	}
	lines = append(lines, "", tuiMuted.Render("按 2 查看全部请求，按 3 只看告警。"))
	return strings.Join(lines, "\n")
}

func (m tuiModel) healthContent() string {
	s := m.snapshot.Stats
	level := func(n uint64) string {
		if n > 0 {
			return tuiWarn.Render(tuiCount(n))
		}
		return tuiCount(n)
	}
	label := func(s string) string { return tuiMuted.Render(tuiCell(s, 14)) }
	lines := []string{tuiWarn.Bold(true).Render("⚠ 完整性未验证"), session.CoverageWarning, ""}
	if m.snapshot.StatusWarning != "" {
		lines = append(lines, tuiDanger.Render(m.snapshot.StatusWarning), "")
	}
	lines = append(lines,
		tuiAccent.Render("采集"),
		label("状态")+tuiStateBadge(s.State)+"    开始于 "+m.startedText(),
		label("网络包")+tuiCount(s.Packets)+"    网卡丢包 "+level(s.Dropped)+"    用户态队列丢弃 "+level(s.QueueDropped),
		label("TLS")+fmt.Sprintf("外层记录 %s    明文请求 %s    已知丢弃 %s", tuiCount(s.TLSWireRecords), tuiCount(s.TLSRequests), level(s.TLSDropped)),
		label("TLS 状态")+tuiLine(s.TLS),
		label("资源限制")+tuiLine(s.ResourceLimits),
		label("告警推送")+fmt.Sprintf("已送达 %s    失败 %s    队列丢弃 %s", tuiCount(s.AlertDelivered), level(s.AlertDeliveryFailed), level(s.AlertDeliveryDropped)),
		"", tuiAccent.Render("服务探针"),
	)
	if len(s.Targets) == 0 {
		lines = append(lines, "暂无服务探针记录")
	} else {
		lines = append(lines, tuiMuted.Render(tuiCell("服务", 12)+tuiCell("PID", 10)+tuiCell("端口", 16)+"状态"))
		for _, target := range s.Targets {
			ports := []string{}
			for _, port := range target.Ports {
				ports = append(ports, fmt.Sprint(port))
			}
			lines = append(lines, tuiCell(tuiLine(target.Service), 12)+tuiCell(fmt.Sprint(target.PID), 10)+tuiCell(strings.Join(ports, ","), 16)+tuiTargetStyle(target.State).Render(tuiLine(target.State)))
		}
	}
	lines = append(lines, "", tuiAccent.Render(fmt.Sprintf("采集错误 (%d)", len(s.Errors))))
	if len(s.Errors) == 0 {
		lines = append(lines, "暂无记录")
	}
	for _, err := range s.Errors {
		lines = append(lines, tuiDanger.Render("• "+cleanTUIText(err)))
	}
	return strings.Join(lines, "\n")
}

func (m tuiModel) detailContent() string {
	if m.snapshot.DetailMissing {
		return "该记录已被保留期清理，按 Esc 返回列表，或按 J/K 查看相邻记录"
	}
	t := m.snapshot.Detail
	if t == nil || t.ID != m.detailID {
		return "正在加载详情…"
	}
	var b strings.Builder
	label := func(s string) string { return tuiMuted.Render(tuiCell(s, 10)) }
	status := tuiStatusStyle(t.Status).Render(fmt.Sprint(t.Status))
	if t.Status == 0 {
		status = tuiMuted.Render("待响应")
	}
	flags := ""
	if t.Incomplete {
		flags += tuiWarn.Render("  [不完整]")
	}
	if t.Truncated {
		flags += tuiWarn.Render("  [截断]")
	}
	b.WriteString(tuiBold.Render(tuiLine(t.Method)+" "+tuiLine(t.URL)) + "\n")
	fmt.Fprintf(&b, "%s%s    %s%s%s\n", label("时间"), t.Time.Local().Format("01-02 15:04:05.000"), tuiMuted.Render("响应 "), status, flags)
	fmt.Fprintf(&b, "%s%s\n", label("客户端"), tuiLine(t.Client))
	if t.PeerClient != "" {
		fmt.Fprintf(&b, "%s%s  %s\n", label("直连对端"), tuiLine(t.PeerClient), tuiMuted.Render("来源依据 "+tuiLine(t.ClientSource)))
	}
	fmt.Fprintf(&b, "%s%s\n", label("Host"), tuiLine(t.Host))
	service := []string{}
	for _, part := range []string{t.Service, pidText(t.PID), backendText(t.Backend), tuiLine(t.Source)} {
		if part != "" {
			service = append(service, tuiLine(part))
		}
	}
	if len(service) > 0 {
		fmt.Fprintf(&b, "%s%s\n", label("服务"), strings.Join(service, " · "))
	}
	if t.Connection != "" || t.LocalEndpoint != "" {
		connection := tuiLine(t.Connection)
		if t.LocalEndpoint != "" {
			connection += tuiMuted.Render("  本地 " + tuiLine(t.LocalEndpoint))
		}
		fmt.Fprintf(&b, "%s%s\n", label("连接"), strings.TrimSpace(connection))
	}
	fmt.Fprintf(&b, "%s%s\n\n", label("ID"), tuiLine(t.ID))
	labels := []string{"请求", "响应", "解码正文", "检测依据"}
	if len(t.Alerts) > 0 {
		labels[3] = fmt.Sprintf("检测依据 %d", len(t.Alerts))
	}
	for i, label := range labels {
		if i == m.detailTab {
			b.WriteString(tuiAccent.Render("[" + label + "]"))
		} else {
			b.WriteString(tuiMuted.Render(label))
		}
		b.WriteString("  ")
	}
	b.WriteString("\n\n")
	switch m.detailTab {
	case 0:
		if len(t.Request) == 0 {
			b.WriteString("暂无请求内容")
		} else {
			b.WriteString(cleanTUIText(session.SafeText(t.Request)))
		}
	case 1:
		if len(t.Response) == 0 {
			b.WriteString("暂无响应内容")
		} else {
			b.WriteString(cleanTUIText(session.SafeText(t.Response)))
		}
	case 2:
		body, view := session.DecodedBody(t.Request, 1<<20)
		if view == "" {
			b.WriteString("暂无可用的 gzip 解码正文，请查看请求标签")
		} else {
			fmt.Fprintf(&b, "解码视图 %s\n\n%s", tuiLine(view), cleanTUIText(body))
		}
	case 3:
		if len(t.Alerts) == 0 {
			b.WriteString("暂无告警")
		}
		for _, a := range t.Alerts {
			fmt.Fprintf(&b, "%s  %s\n%s\n%s\n%s\n\n", tuiSeverityStyle(a.Severity).Bold(true).Render(tuiLine(a.Rule)), tuiMuted.Render(fmt.Sprintf("版本 %d · 级别 %s · 字段 %s", a.Version, tuiSeverity(a.Severity), tuiLine(a.Field))), tuiMuted.Render(fmt.Sprintf("视图 %s · 解码 %d 轮", alertView(a.View), a.Decoding)), tuiMuted.Render("匹配片段"), cleanTUIText(a.Match))
		}
	}
	return b.String()
}
func alertView(view string) string {
	if view == "" {
		return "原文"
	}
	return tuiLine(view)
}
func pidText(pid int) string {
	if pid == 0 {
		return ""
	}
	return fmt.Sprintf("PID %d", pid)
}
func backendText(backend string) string {
	if backend == "" {
		return ""
	}
	return "后端 " + backend
}

// listView adapts columns to width: narrow keeps time, method, status, level and URL.
func (m tuiModel) listView(width, height int) string {
	if m.stale {
		return "正在加载…"
	}
	now := time.Now()
	today := true
	for _, r := range m.snapshot.Rows {
		if !tuiIsToday(r.Time, now) {
			today = false
			break
		}
	}
	timeWidth := 15
	if today {
		timeWidth = 10
	}
	showClient, showHost := width >= 80, width >= 100
	clientWidth, hostWidth := 0, 0
	if showClient {
		clientWidth = 17
		for _, r := range m.snapshot.Rows {
			clientWidth = max(clientWidth, min(41, lipgloss.Width(tuiLine(m.clientText(r, width)))+2))
		}
	}
	if showHost {
		hostWidth = 12
		for _, r := range m.snapshot.Rows {
			hostWidth = max(hostWidth, min(28, lipgloss.Width(tuiLine(r.Host))+2))
		}
	}
	header := tuiCell("时间", timeWidth) + tuiCell("方法", 7) + tuiCell("状态", 7) + tuiCell("级", 3)
	if showClient {
		header += tuiCell("客户端", clientWidth)
	}
	if showHost {
		header += tuiCell("Host", hostWidth)
	}
	lines := []string{tuiMuted.Render(termansi.Truncate(header+"URL", width, "…"))}
	visible := max(1, height-2)
	start := max(0, m.selected-visible+1)
	for i := start; i < min(len(m.snapshot.Rows), start+visible); i++ {
		r := m.snapshot.Rows[i]
		status := "待响应"
		if r.Status != 0 {
			status = fmt.Sprint(r.Status)
		}
		url := ""
		if r.Incomplete {
			url += "[不完整] "
		}
		if r.Truncated {
			url += "[截断] "
		}
		url += tuiLine(r.URL)
		cells := []struct {
			text  string
			width int
			style lipgloss.Style
		}{
			{tuiShortTime(r.Time, today), timeWidth, lipgloss.NewStyle()},
			{tuiLine(r.Method), 7, lipgloss.NewStyle()},
			{status, 7, tuiStatusStyle(r.Status)},
			{tuiSeverity(r.Severity), 3, tuiSeverityStyle(r.Severity)},
		}
		if showClient {
			cells = append(cells, struct {
				text  string
				width int
				style lipgloss.Style
			}{tuiLine(m.clientText(r, width)), clientWidth, lipgloss.NewStyle()})
		}
		if showHost {
			cells = append(cells, struct {
				text  string
				width int
				style lipgloss.Style
			}{tuiLine(r.Host), hostWidth, tuiMuted})
		}
		used := 0
		for _, c := range cells {
			used += c.width
		}
		urlWidth := max(1, width-used)
		urlStyle := lipgloss.NewStyle()
		if r.Severity == "high" {
			urlStyle = tuiDanger
		}
		var line strings.Builder
		if i == m.selected {
			// Selection is drawn uncolored so the reverse video spans the whole row.
			for _, c := range cells {
				line.WriteString(tuiCell(c.text, c.width))
			}
			line.WriteString(tuiCell(url, urlWidth))
			lines = append(lines, tuiSelected.Render(termansi.Truncate(line.String(), width, "")))
			continue
		}
		for _, c := range cells {
			line.WriteString(c.style.Render(tuiCell(c.text, c.width)))
		}
		line.WriteString(urlStyle.Render(termansi.Truncate(url, urlWidth, "…")))
		lines = append(lines, termansi.Truncate(line.String(), width, ""))
	}
	if len(m.snapshot.Rows) == 0 {
		if m.filter != (tuiFilter{}) {
			lines = append(lines, "当前筛选无匹配，按 x 清空筛选")
		} else if m.tab == tabAlerts {
			lines = append(lines, "暂无告警")
		} else {
			lines = append(lines, "暂无请求")
		}
	}
	for len(lines) < height-1 {
		lines = append(lines, "")
	}
	pager := tuiMuted.Render(fmt.Sprintf("第 %d/%d 页 · 共 %s 条", m.page+1, max(1, (m.snapshot.Count+99)/100), tuiCount(uint64(m.snapshot.Count))))
	if !m.following() && !m.paused {
		if m.page == 0 && m.snapshot.Newer > 0 {
			pager += tuiAccent.Render(fmt.Sprintf(" · ↑ 新增 %s 条，按 g 回到最新", tuiCount(uint64(m.snapshot.Newer))))
		} else if m.page > 0 {
			pager += tuiMuted.Render(" · 按 g 回到最新")
		}
	}
	lines = append(lines, termansi.Truncate(pager, width, "…"))
	return strings.Join(lines, "\n")
}

// clientText hides the client port on medium widths.
func (m tuiModel) clientText(r tuiRow, width int) string {
	if width >= 120 {
		return r.Client
	}
	return tuiClientHost(r.Client)
}

func (m tuiModel) filterChips() []string {
	f := m.filter
	chips := []string{}
	add := func(value, label string) {
		if value != "" {
			chips = append(chips, "["+label+tuiLine(value)+"]")
		}
	}
	if f.Severity != "" {
		chips = append(chips, "[级别 ≥ "+tuiSeverity(f.Severity)+"]")
	}
	if f.Since != "" {
		if t, err := time.Parse(indexTimeFormat, f.Since); err == nil {
			chips = append(chips, "[时间 ≥ "+t.Local().Format("01-02 15:04:05")+"]")
		} else {
			add(f.Since, "时间 ≥ ")
		}
	}
	add(f.Client, "客户端 = ")
	add(f.Rule, "规则 = ")
	add(f.Service, "服务 = ")
	add(f.Keyword, "关键词 ")
	return chips
}
func (m tuiModel) filterLabel() string {
	chips := m.filterChips()
	if len(chips) == 0 {
		return tuiMuted.Render("筛选  全部")
	}
	line := tuiMuted.Render("筛选  ") + strings.Join(chips, " ")
	if m.listTab() {
		line += tuiMuted.Render(fmt.Sprintf("  共 %s 条 · x 清空", tuiCount(uint64(m.snapshot.Count))))
	} else {
		line += tuiMuted.Render("  · 本页不受筛选影响")
	}
	return line
}

func (m tuiModel) identityLine(width int) string {
	title := m.title
	if title == "" {
		title = filepath.Base(m.store.dir)
	}
	s := m.snapshot.Stats
	left := tuiAccent.Render("TRAFFIC") + "  " + tuiLine(title) + "  " + tuiStateBadge(s.State)
	mode := ""
	switch {
	case m.paused:
		mode = tuiWarn.Render("已暂停")
	case !tuiLive(s.State):
	case m.listTab() && !m.following():
		mode = "已定格"
	case m.listTab():
		mode = "跟随最新"
	default:
		mode = "自动刷新"
	}
	right := fmt.Sprintf("请求 %s · 告警 %s", tuiCount(s.Transactions), tuiCount(s.Alerts))
	if mode != "" {
		right += " · " + mode
	}
	return tuiSpread(left, tuiMuted.Render(right), width)
}
func (m tuiModel) tabsLine(width int) string {
	level, _ := m.tuiHealth()
	alerts := ""
	if m.snapshot.Stats.Alerts > 0 {
		alerts = " " + tuiCount(m.snapshot.Stats.Alerts)
	}
	mark := ""
	switch level {
	case 1:
		mark = " !"
	case 2:
		mark = " ✕"
	}
	labels := []string{"1 概览", "2 请求", "3 告警" + alerts, "4 健康" + mark}
	parts := make([]string, len(labels))
	for i, label := range labels {
		switch {
		case i == m.tab:
			parts[i] = tuiAccent.Render("[" + label + "]")
		case i == tabAlerts && alerts != "":
			parts[i] = tuiDanger.Render(label)
		case i == tabHealth && level == 2:
			parts[i] = tuiDanger.Render(label)
		case i == tabHealth && level == 1:
			parts[i] = tuiWarn.Render(label)
		default:
			parts[i] = tuiMuted.Render(label)
		}
	}
	return tuiSpread(strings.Join(parts, "   "), tuiMuted.Render("本地时间 "+time.Now().Format("MST -07:00")), width)
}
func (m tuiModel) noticeLine() string {
	if m.errorText != "" {
		return tuiDanger.Render("刷新失败，保留上次结果 · " + tuiLine(m.errorText))
	}
	if m.flash != "" {
		return tuiAccent.Render(tuiLine(m.flash))
	}
	level, reasons := m.tuiHealth()
	if level == 0 {
		return ""
	}
	text := "⚠ " + strings.Join(reasons, " · ")
	if m.tab != tabHealth {
		text += " · 按 4 查看"
	}
	if level == 2 {
		return tuiDanger.Render(text)
	}
	return tuiWarn.Render(text)
}
func (m tuiModel) keysLine() string {
	switch {
	case m.form != nil:
		return "Tab/↑↓ 换行 · ←→ 选项 · Enter 应用 · Ctrl+R 清空 · Esc 取消"
	case m.export != nil:
		return "Enter 导出 · Esc 取消"
	case m.help:
		return "? 或 Esc 关闭帮助 · q 退出"
	case m.details:
		return "↑↓ 滚动 · J/K 上下一条 · Tab 切标签 · c 同客户端 · m 同规则 · H 同 Host · e 导出 · Esc 返回"
	case m.listTab():
		return "↑↓ 选择 · Enter 详情 · / 筛选 · c/m/H 按选中行筛选 · x 清空 · e 导出 · g 最新 · 空格 暂停 · s 会话 · ? 帮助"
	}
	return "1-4 切换页面 · ↑↓ 滚动 · / 筛选 · 空格 暂停 · r 刷新 · s 会话 · ? 帮助 · q 退出"
}

const tuiHelpText = `快捷键

页面    1 概览   2 请求   3 告警   4 采集健康   s 回到会话选择
移动    ↑↓ / j k 选择或滚动    g 回到最新并恢复跟随    G 本页末尾
        n p / ← → / PgDn PgUp 翻页
层级    Enter 打开详情    Esc 关闭弹层或详情
详情    Tab / Shift+Tab 切换请求、响应、解码正文、检测依据
        J / K 不退出详情查看下一条、上一条
筛选    / 打开筛选面板    x 清空全部筛选
        c 只看选中行的客户端    m 只看它命中的规则    H 只看它的 Host
        再按一次同一个键取消该条件
证据    e 导出选中请求的证据压缩包（需要先停止采集）
刷新    光标在第一页第一行时跟随最新记录，离开后列表定格
        空格 暂停或恢复    r 立即刷新
退出    q 或 Ctrl+C`

func (m tuiModel) View() tea.View {
	width, height := max(1, m.width), max(1, m.height)
	contentHeight := m.contentHeight()
	content := m.viewport.View()
	switch {
	case m.help:
		content = tuiHelpText
	case m.form != nil:
		content = m.form.view(contentHeight)
	case m.export != nil:
		content = m.export.view()
	case m.split():
		listWidth := width / 2
		content = lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(listWidth).Render(m.listView(listWidth-1, contentHeight)), tuiMuted.Render(" │ "), m.viewport.View())
	case m.listTab() && !m.details:
		content = m.listView(width, contentHeight)
	}
	frame := m.identityLine(width) + "\n" + m.tabsLine(width) + "\n" + termansi.Truncate(m.filterLabel(), width, "…") + "\n" +
		lipgloss.NewStyle().Height(contentHeight).MaxHeight(contentHeight).Render(content) + "\n" +
		termansi.Truncate(m.noticeLine(), width, "…") + "\n" + tuiMuted.Render(termansi.Truncate(m.keysLine(), width, "…"))
	if width < 40 || height < 12 {
		frame = "终端过小，请调整到至少 40 列 × 12 行\nCtrl+C 退出"
	}
	view := tea.NewView(lipgloss.NewStyle().MaxWidth(width).MaxHeight(height).Render(frame))
	view.AltScreen = true
	return view
}

// tuiForm edits the filter; level and service are choices, the rest are text.
type tuiFormField struct {
	label, hint string
	values      []string
	names       []string
	choice      int
	input       textinput.Model
}
type tuiForm struct {
	fields []tuiFormField
	index  int
	err    string
	now    func() time.Time
}

const (
	formSeverity = iota
	formSince
	formClient
	formRule
	formService
	formKeyword
)

func newTUIForm(f tuiFilter, services []string, width int) *tuiForm {
	text := func(label, hint, value string) tuiFormField {
		input := textinput.New()
		input.SetVirtualCursor(true)
		input.SetValue(value)
		input.Placeholder = hint
		input.SetWidth(max(10, width-24))
		input.CharLimit = 512
		return tuiFormField{label: label, input: input}
	}
	since := ""
	if t, err := time.Parse(indexTimeFormat, f.Since); err == nil {
		since = t.Local().Format("2006-01-02 15:04:05")
	}
	form := &tuiForm{now: time.Now}
	severity := tuiFormField{label: "级别", values: []string{"", "low", "medium", "high"}, names: []string{"全部", "低及以上", "中及以上", "仅高"}}
	service := tuiFormField{label: "服务", values: append([]string{""}, services...), names: append([]string{"全部"}, services...)}
	for i, v := range severity.values {
		if v == f.Severity {
			severity.choice = i
		}
	}
	for i, v := range service.values {
		if v == f.Service {
			service.choice = i
		}
	}
	form.fields = []tuiFormField{
		severity,
		text("时间从", "30m、2h、1d、today、14:30、11-16 14:30 或 RFC3339", since),
		text("客户端", "IP 或 IP:端口", f.Client),
		text("规则", "规则 ID，例如 SQLI-001", f.Rule),
		service,
		text("关键词", "Host 或 URL 包含的文字", f.Keyword),
	}
	return form
}
func (f *tuiForm) focus() tea.Cmd {
	for i := range f.fields {
		f.fields[i].input.Blur()
	}
	if f.fields[f.index].values == nil {
		return f.fields[f.index].input.Focus()
	}
	return nil
}
func (f *tuiForm) update(msg tea.Msg) tea.Cmd {
	field := &f.fields[f.index]
	if field.values != nil {
		return nil
	}
	var cmd tea.Cmd
	field.input, cmd = field.input.Update(msg)
	return cmd
}
func (f *tuiForm) filter() (tuiFilter, error) {
	value := func(i int) string { return strings.TrimSpace(f.fields[i].input.Value()) }
	choice := func(i int) string { return f.fields[i].values[f.fields[i].choice] }
	filter := tuiFilter{Severity: choice(formSeverity), Client: value(formClient), Rule: value(formRule), Service: choice(formService), Keyword: value(formKeyword)}
	if since := value(formSince); since != "" {
		t, err := parseTUISince(since, f.now())
		if err != nil {
			return filter, err
		}
		filter.Since = t.UTC().Format(indexTimeFormat)
	}
	return filter, nil
}
func (f *tuiForm) view(height int) string {
	lines := []string{tuiAccent.Render("筛选"), ""}
	compact := height < 16
	for i, field := range f.fields {
		if compact && i != f.index {
			continue
		}
		label := tuiCell(field.label, 10)
		if i == f.index {
			label = tuiAccent.Render(label)
		} else {
			label = tuiMuted.Render(label)
		}
		if field.values == nil {
			lines = append(lines, label+field.input.View())
			continue
		}
		options := []string{}
		for j, name := range field.names {
			if j == field.choice {
				options = append(options, tuiAccent.Render("["+tuiLine(name)+"]"))
			} else {
				options = append(options, tuiMuted.Render(" "+tuiLine(name)+" "))
			}
		}
		lines = append(lines, label+strings.Join(options, " "))
	}
	if compact {
		lines = append(lines, tuiMuted.Render(fmt.Sprintf("字段 %d/%d", f.index+1, len(f.fields))))
	}
	lines = append(lines, "")
	if since := strings.TrimSpace(f.fields[formSince].input.Value()); since != "" {
		if t, err := parseTUISince(since, f.now()); err == nil {
			lines = append(lines, tuiMuted.Render("时间从 = "+t.Local().Format("2006-01-02 15:04:05 MST")+" 起"))
		} else {
			lines = append(lines, tuiWarn.Render("时间从 "+err.Error()))
		}
	}
	lines = append(lines, tuiMuted.Render("级别按「不低于」筛选；规则和级别需要同一条告警同时满足"))
	if f.err != "" {
		lines = append(lines, tuiDanger.Render(f.err))
	}
	return strings.Join(lines, "\n")
}
func (m *tuiModel) updateForm(msg tea.KeyPressMsg) tea.Cmd {
	f := m.form
	field := &f.fields[f.index]
	switch msg.String() {
	case "esc":
		m.form = nil
		return nil
	case "tab", "down":
		f.index = (f.index + 1) % len(f.fields)
		return f.focus()
	case "shift+tab", "up":
		f.index = (f.index + len(f.fields) - 1) % len(f.fields)
		return f.focus()
	case "left", "right":
		if field.values != nil {
			step := 1
			if msg.String() == "left" {
				step = len(field.values) - 1
			}
			field.choice = (field.choice + step) % len(field.values)
			return nil
		}
	case "ctrl+r":
		for i := range f.fields {
			f.fields[i].input.SetValue("")
			f.fields[i].choice = 0
		}
		f.err = ""
		return nil
	case "enter":
		filter, err := f.filter()
		if err != nil {
			f.err = "时间从 " + err.Error()
			return nil
		}
		m.form = nil
		return m.applyFilter(filter)
	}
	return f.update(msg)
}

// parseTUISince accepts relative durations and local clock times as well as RFC3339.
func parseTUISince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	now = now.Local()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	switch strings.ToLower(s) {
	case "today", "今天":
		return midnight, nil
	case "yesterday", "昨天":
		return midnight.AddDate(0, 0, -1), nil
	}
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil && days > 0 && fmt.Sprintf("%dd", days) == s {
			return now.AddDate(0, 0, -days), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	for _, layout := range []string{"01-02 15:04:05", "01-02 15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
			if t.After(now) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, nil
		}
	}
	for _, layout := range []string{"15:04:05", "15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			t = time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
			if t.After(now) {
				t = t.AddDate(0, 0, -1)
			}
			return t, nil
		}
	}
	return time.Time{}, errors.New("无法识别，可填 30m、2h、1d、today、14:30、11-16 14:30 或 2026-11-11T10:00:00+08:00")
}

// tuiExport collects the destination for one record's evidence archive.
type tuiExport struct {
	id, label, state string
	input            textinput.Model
	err              string
	running          bool
}

func (m *tuiModel) openExport() tea.Cmd {
	row, ok := m.currentRow()
	if !ok {
		m.flash = "没有选中的请求"
		return nil
	}
	input := textinput.New()
	input.SetVirtualCursor(true)
	input.CharLimit = 4096
	input.SetWidth(max(10, m.width-6))
	input.SetValue("./evidence-" + tuiFileSafe(row.ID) + ".zip")
	m.export = &tuiExport{id: row.ID, label: tuiLine(row.Method + " " + row.URL), state: m.snapshot.Stats.State, input: input}
	return m.export.input.Focus()
}
func tuiFileSafe(s string) string {
	safe := strings.Map(func(r rune) rune {
		if r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == '_') {
			return r
		}
		return '_'
	}, s)
	if len(safe) > 64 {
		safe = safe[:64]
	}
	return safe
}
func (e *tuiExport) view() string {
	lines := []string{tuiAccent.Render("导出证据"), "", tuiMuted.Render("请求  ") + e.label, "", tuiMuted.Render("保存到"), e.input.View(), "",
		tuiMuted.Render("包含请求、响应、事件 JSON、关联 PCAP 和 SHA-256 清单。目标文件必须不存在。")}
	if e.state == "running" {
		lines = append(lines, tuiWarn.Render("采集仍在进行。导出需要采集锁，请先停止采集。"))
	}
	if e.running {
		lines = append(lines, "", tuiAccent.Render("正在导出…"))
	}
	if e.err != "" {
		lines = append(lines, "", tuiDanger.Render(e.err))
	}
	return strings.Join(lines, "\n")
}
func (m *tuiModel) updateExport(msg tea.KeyPressMsg) tea.Cmd {
	e := m.export
	switch msg.String() {
	case "esc":
		m.export = nil
		return nil
	case "enter":
		if e.running {
			return nil
		}
		path := strings.TrimSpace(e.input.Value())
		if path == "" {
			e.err = "请输入保存路径"
			return nil
		}
		if path == "~" || strings.HasPrefix(path, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				path = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
			}
		}
		if absolute, err := filepath.Abs(path); err == nil {
			path = absolute
		}
		e.running, e.err = true, ""
		store, id := m.store, e.id
		return func() tea.Msg {
			var b []byte
			if err := store.db.QueryRow("SELECT data FROM requests WHERE id=?", id).Scan(&b); err != nil {
				return tuiExported{ID: id, Err: err}
			}
			var t Transaction
			if err := json.Unmarshal(b, &t); err != nil {
				return tuiExported{ID: id, Err: err}
			}
			if err := exportEvidence(store, t, b, path); err != nil {
				return tuiExported{ID: id, Err: err}
			}
			var size int64
			if info, err := os.Stat(path); err == nil {
				size = info.Size()
			}
			return tuiExported{ID: id, Path: path, Size: size}
		}
	}
	var cmd tea.Cmd
	e.input, cmd = e.input.Update(msg)
	return cmd
}
func tuiExportError(err error) string {
	switch {
	case errors.Is(err, errCaptureRunning):
		return "导出失败：采集仍在进行，停止采集后再导出"
	case errors.Is(err, fs.ErrExist):
		return "导出失败：目标文件已存在，请换一个文件名"
	case errors.Is(err, sql.ErrNoRows):
		return "导出失败：该记录已被保留期清理"
	}
	return "导出失败：" + cleanTUIText(err.Error())
}
