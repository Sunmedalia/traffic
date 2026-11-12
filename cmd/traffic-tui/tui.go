package main

import (
	"context"
	"fmt"
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

type tuiTick time.Time
type tuiLoaded struct {
	Version  uint64
	Snapshot tuiSnapshot
	Err      error
}

type tuiModel struct {
	ctx                                             context.Context
	store                                           *Store
	refresh                                         time.Duration
	filter                                          tuiFilter
	snapshot                                        tuiSnapshot
	width, height, tab, page, selected, detailTab   int
	version                                         uint64
	busy, pending, paused, details, help, filtering bool
	detailID, errorText, formError                  string
	inputs                                          []textinput.Model
	inputIndex                                      int
	viewport                                        viewport.Model
}

var tuiAccent = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#5FD7D7"))
var tuiMuted = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
var tuiSelected = lipgloss.NewStyle().Reverse(true)
var tuiDanger = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF7777"))

func (m tuiModel) tick() tea.Cmd {
	return tea.Tick(m.refresh, func(t time.Time) tea.Msg { return tuiTick(t) })
}
func (m tuiModel) Init() tea.Cmd { return m.tick() }
func (m *tuiModel) load() tea.Cmd {
	if m.busy {
		m.pending = true
		return nil
	}
	m.busy = true
	m.pending = false
	version, filter, page, alertsOnly, detailID := m.version, m.filter, m.page, m.tab == 2, m.detailID
	var anchor *tuiRow
	if page > 0 && m.snapshot.Page == page && len(m.snapshot.Rows) > 0 {
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
func (m *tuiModel) changed() tea.Cmd { m.version++; return m.load() }
func (m *tuiModel) resize() {
	width := max(1, m.width-2)
	if m.details && m.width >= 120 {
		width = max(1, m.width-m.width/2-3)
	}
	m.viewport.SetWidth(width)
	m.viewport.SetHeight(max(1, m.height-8))
	m.updateContent()
}
func (m *tuiModel) updateContent() {
	content := m.overview()
	if m.details {
		content = m.detailContent()
	}
	m.viewport.SetContent(termansi.Hardwrap(content, max(1, m.viewport.Width()), true))
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		for i := range m.inputs {
			m.inputs[i].SetWidth(max(10, msg.Width-20))
		}
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
				selectedID := ""
				if len(m.snapshot.Rows) > m.selected {
					selectedID = m.snapshot.Rows[m.selected].ID
				}
				m.snapshot, m.page = msg.Snapshot, msg.Snapshot.Page
				m.selected = min(m.selected, max(0, len(m.snapshot.Rows)-1))
				for i, row := range m.snapshot.Rows {
					if row.ID == selectedID {
						m.selected = i
						break
					}
				}
				m.errorText = ""
				m.updateContent()
			}
		}
		if m.pending || msg.Version != m.version {
			return m, m.load()
		}
		return m, nil
	case tea.KeyPressMsg:
		key := msg.String()
		if key == "ctrl+c" {
			return m, tea.Quit
		}
		if m.filtering {
			return m.updateForm(msg)
		}
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
			return m, m.openForm()
		case " ", "space":
			m.paused = !m.paused
			if !m.paused {
				return m, m.load()
			}
			return m, nil
		case "r":
			return m, m.load()
		case "1", "2", "3":
			m.tab = int(key[0] - '1')
			m.page = 0
			m.selected = 0
			m.details = false
			m.detailID = ""
			m.viewport.GotoTop()
			m.resize()
			return m, m.changed()
		case "esc":
			m.details = false
			m.detailID = ""
			m.viewport.GotoTop()
			m.resize()
			return m, m.changed()
		}
		if m.details || m.tab == 0 {
			if m.details && (key == "tab" || key == "shift+tab") {
				step := 1
				if key == "shift+tab" {
					step = 3
				}
				m.detailTab = (m.detailTab + step) % 4
				m.viewport.GotoTop()
				m.updateContent()
				return m, nil
			}
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
			m.selected = 0
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
				m.details = true
				m.detailID = m.snapshot.Rows[m.selected].ID
				m.snapshot.Detail = nil
				m.snapshot.DetailMissing = false
				m.detailTab = 0
				m.viewport.GotoTop()
				m.resize()
				return m, m.changed()
			}
		}
	}
	if m.filtering {
		var cmd tea.Cmd
		m.inputs[m.inputIndex], cmd = m.inputs[m.inputIndex].Update(msg)
		return m, cmd
	}
	return m, nil
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
func (m tuiModel) overview() string {
	s := m.snapshot.Stats
	started := "未知"
	if !s.Started.IsZero() {
		started = s.Started.Local().Format("2006-01-02 15:04:05 MST -07:00")
	}
	lines := []string{
		tuiAccent.Render("采集概览"), "",
		"会话  " + tuiLine(m.store.dir),
		"状态  " + tuiState(s.State),
		"开始  " + started, "",
		fmt.Sprintf("累计请求  %d    累计告警命中  %d", s.Transactions, s.Alerts),
		fmt.Sprintf("网络包    %d", s.Packets), "",
		fmt.Sprintf("网卡丢包  %d    用户态队列丢弃  %d    TLS 丢失  %d", s.Dropped, s.QueueDropped, s.TLSDropped),
		"TLS   " + tuiLine(s.TLS),
		"资源  " + tuiLine(s.ResourceLimits), "",
	}
	for _, target := range s.Targets {
		lines = append(lines, fmt.Sprintf("服务 %s · PID %d · %s", tuiLine(target.Service), target.PID, tuiLine(target.State)))
	}
	if m.snapshot.StatusWarning != "" {
		lines = append(lines, tuiDanger.Render(m.snapshot.StatusWarning), "")
	}
	lines = append(lines, tuiAccent.Render("采集错误"))
	if len(s.Errors) == 0 {
		lines = append(lines, "暂无记录")
	}
	for _, err := range s.Errors {
		lines = append(lines, "• "+cleanTUIText(err))
	}
	return strings.Join(lines, "\n")
}
func (m tuiModel) detailContent() string {
	if m.snapshot.DetailMissing {
		return "该记录已被保留期清理，按 Esc 返回列表"
	}
	t := m.snapshot.Detail
	if t == nil || t.ID != m.detailID {
		return "正在加载详情…"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s  %s  %s\n客户端 %s\nHost %s\n来源 %s  PID %d\n连接 %s\n响应 %d  不完整 %t  截断 %t\n\n",
		tuiLine(t.ID), tuiTime(t.Time.Format(time.RFC3339Nano)), tuiLine(t.Method), tuiLine(t.URL), tuiLine(t.Client), tuiLine(t.Host), tuiLine(t.Source), t.PID, tuiLine(t.Connection), t.Status, t.Incomplete, t.Truncated)
	fmt.Fprintf(&b, "服务 %s  目标 %s\n后端 %s  本地 %s\n\n", tuiLine(t.Service), tuiLine(t.TargetID), tuiLine(t.Backend), tuiLine(t.LocalEndpoint))
	labels := []string{"请求", "响应", "解码正文", "检测依据"}
	for i, label := range labels {
		if i == m.detailTab {
			b.WriteString(tuiAccent.Render("[" + label + "]"))
		} else {
			b.WriteString(label)
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
			fmt.Fprintf(&b, "%s  版本 %d  级别 %s\n字段 %s  视图 %s  解码轮次 %d\n匹配片段\n%s\n\n", tuiLine(a.Rule), a.Version, tuiSeverity(a.Severity), tuiLine(a.Field), tuiLine(a.View), a.Decoding, cleanTUIText(a.Match))
		}
	}
	return b.String()
}

func (m tuiModel) listView(width, height int) string {
	lines := []string{tuiMuted.Render("时间          方法  状态  级别  客户端 / Host / URL")}
	visible := max(1, height-2)
	start := max(0, m.selected-visible+1)
	for i := start; i < min(len(m.snapshot.Rows), start+visible); i++ {
		r := m.snapshot.Rows[i]
		status := "待响应"
		if r.Status != 0 {
			status = fmt.Sprint(r.Status)
		}
		flags := ""
		if r.Incomplete {
			flags += " [不完整]"
		}
		if r.Truncated {
			flags += " [截断]"
		}
		line := fmt.Sprintf("%s %-6s %s %s%s  %s %s %s", tuiTime(r.Time), tuiLine(r.Method), status, tuiSeverity(r.Severity), flags, tuiLine(r.Client), tuiLine(r.Host), tuiLine(r.URL))
		line = termansi.Truncate(line, max(1, width), "…")
		if i == m.selected {
			line = tuiSelected.Render(line)
		} else if r.Severity == "high" {
			line = tuiDanger.Render(line)
		}
		lines = append(lines, line)
	}
	if len(m.snapshot.Rows) == 0 {
		lines = append(lines, "暂无匹配请求")
	}
	lines = append(lines, tuiMuted.Render(fmt.Sprintf("第 %d/%d 页 · 共 %d 条 · n/p 翻页", m.page+1, max(1, (m.snapshot.Count+99)/100), m.snapshot.Count)))
	return strings.Join(lines, "\n")
}
func (m tuiModel) filterLabel() string {
	parts := []string{}
	values := []string{m.filter.Client, m.filter.Rule, m.filter.Severity, m.filter.Since, m.filter.Keyword, m.filter.Service}
	names := []string{"客户端", "规则", "级别", "起始时间", "关键词", "服务"}
	for i, value := range values {
		if value != "" {
			parts = append(parts, names[i]+"="+tuiLine(value))
		}
	}
	if len(parts) == 0 {
		return "筛选  全部"
	}
	return "筛选  " + strings.Join(parts, "  ")
}
func (m tuiModel) View() tea.View {
	width, height := max(1, m.width), max(1, m.height)
	tabs := []string{"1 概览", "2 请求", "3 告警"}
	for i := range tabs {
		if m.tab == i {
			tabs[i] = tuiAccent.Render("[" + tabs[i] + "]")
		}
	}
	mode := "自动刷新"
	if m.paused {
		mode = "已暂停刷新"
	}
	if m.busy {
		mode += " · 加载中"
	}
	header := strings.Join(tabs, "   ") + "   " + mode
	zoneLabel := "本地时间 " + time.Now().Format("MST -07:00")
	content := m.viewport.View()
	if m.tab != 0 && !m.details {
		content = m.listView(width-2, max(1, height-8))
	}
	if m.details && width >= 120 {
		content = lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(width/2).Render(m.listView(width/2-2, max(1, height-8))), " │ ", m.viewport.View())
	}
	if m.help {
		content = "快捷键\n\n1/2/3  概览 / 请求 / 告警\n↑↓ j/k  选择或滚动   g/G  首尾\nn/p ←→ PgDn/PgUp  翻页\nEnter  打开详情   Tab/Shift+Tab  切换详情标签\n/  筛选   空格  暂停或恢复刷新   r  手动刷新\nEsc  返回列表   s  切换会话   ?  帮助   q/Ctrl+C  退出\n\n筛选面板用 Tab 切换字段，Enter 应用，Ctrl+R 清空。\n详情内 PgUp/PgDn 滚动，Esc 返回列表。"
	}
	if m.filtering {
		content = m.formView()
	}
	notice := m.errorText
	if notice != "" {
		notice = "刷新失败，保留上次结果 · " + notice
	} else {
		notice = m.snapshot.StatusWarning
	}
	footer := "s 会话 · / 筛选 · Enter 详情 · 空格 暂停 · r 刷新 · ? 帮助 · q 退出"
	frame := header + "\n" + tuiMuted.Render(zoneLabel) + "\n" + tuiMuted.Render(termansi.Truncate(m.filterLabel(), width, "…")) + "\n\n" +
		lipgloss.NewStyle().Height(max(1, height-8)).Render(content) + "\n" + tuiDanger.Render(termansi.Truncate(notice, width, "…")) + "\n" + tuiMuted.Render(footer)
	// Clip the final frame as well, including help/forms on very small terminals.
	if width < 40 || height < 12 {
		frame = "终端过小，请调整到至少 40 列 × 12 行\nCtrl+C 退出"
	}
	view := tea.NewView(lipgloss.NewStyle().MaxWidth(width).MaxHeight(height).Render(frame))
	view.AltScreen = true
	return view
}

func (m *tuiModel) openForm() tea.Cmd {
	m.filtering = true
	m.inputIndex = 0
	m.formError = ""
	values := []string{m.filter.Client, m.filter.Rule, m.filter.Severity, m.filter.Since, m.filter.Keyword, m.filter.Service}
	m.inputs = make([]textinput.Model, len(values))
	for i, value := range values {
		input := textinput.New()
		input.SetVirtualCursor(true)
		input.SetValue(value)
		input.SetWidth(max(10, m.width-20))
		input.CharLimit = 512
		m.inputs[i] = input
	}
	return m.inputs[0].Focus()
}
func (m tuiModel) formView() string {
	labels := []string{"客户端 IP / 端点", "规则 ID", "级别 low/medium/high", "起始时间 RFC3339", "Host / URL 关键词", "服务 nginx/apache/tomcat/openssl"}
	lines := []string{tuiAccent.Render("筛选"), ""}
	for i, label := range labels {
		if m.height < 25 && i != m.inputIndex {
			continue
		}
		lines = append(lines, label+"\n"+m.inputs[i].View())
	}
	if m.height < 25 {
		lines = append(lines, fmt.Sprintf("字段 %d/%d", m.inputIndex+1, len(labels)))
	}
	lines = append(lines, "", tuiDanger.Render(m.formError), "Tab 切换 · Enter 应用 · Ctrl+R 清空 · Esc 取消")
	return strings.Join(lines, "\n")
}
func (m *tuiModel) updateForm(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filtering = false
		return m, nil
	case "tab", "shift+tab":
		m.inputs[m.inputIndex].Blur()
		step := 1
		if msg.String() == "shift+tab" {
			step = len(m.inputs) - 1
		}
		m.inputIndex = (m.inputIndex + step) % len(m.inputs)
		return m, m.inputs[m.inputIndex].Focus()
	case "ctrl+r":
		for i := range m.inputs {
			m.inputs[i].SetValue("")
		}
		m.formError = ""
		return m, nil
	case "enter":
		values := make([]string, len(m.inputs))
		for i := range m.inputs {
			values[i] = strings.TrimSpace(m.inputs[i].Value())
		}
		filter := tuiFilter{Client: values[0], Rule: values[1], Severity: values[2], Since: values[3], Keyword: values[4], Service: values[5]}
		if filter.Severity != "" && filter.Severity != "low" && filter.Severity != "medium" && filter.Severity != "high" {
			m.formError = "级别请输入 low、medium 或 high"
			return m, nil
		}
		if filter.Since != "" {
			t, err := time.Parse(time.RFC3339, filter.Since)
			if err != nil {
				m.formError = "时间格式示例 2026-11-11T10:00:00+08:00"
				return m, nil
			}
			filter.Since = t.UTC().Format(indexTimeFormat)
		}
		m.filter = filter
		m.page = 0
		m.selected = 0
		m.details = false
		m.detailID = ""
		m.filtering = false
		m.resize()
		return m, m.changed()
	}
	var cmd tea.Cmd
	m.inputs[m.inputIndex], cmd = m.inputs[m.inputIndex].Update(msg)
	return m, cmd
}
