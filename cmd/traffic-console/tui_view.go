package main

// Rendering of the TUI pages: health, list, detail and chrome lines.

import (
	lipgloss "charm.land/lipgloss/v2"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/traffic/internal/session"
)

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
	case "interrupted":
		warn(2, "采集未正常结束")
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
	if s.ProbeFailures > 0 {
		warn(1, fmt.Sprintf("探针传输失败 %d 次", s.ProbeFailures))
	}
	if len(s.IntegrityWarnings) > 0 {
		warn(1, fmt.Sprintf("完整性告警 %d 项", len(s.IntegrityWarnings)))
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
	if len(s.IntegrityWarnings) > 0 {
		lines = append(lines, tuiWarn.Bold(true).Render(fmt.Sprintf("完整性风险提示 (%d)", len(s.IntegrityWarnings))))
		for _, w := range s.IntegrityWarnings {
			lines = append(lines, tuiWarn.Render("• "+cleanTUIText(w)))
		}
		lines = append(lines, "")
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
	if s.DrainState != "" {
		lines = append(lines, "数据排空  "+tuiLine(s.DrainState))
	}
	if len(s.GapCounts) > 0 {
		data, _ := json.Marshal(s.GapCounts)
		lines = append(lines, "采集缺口  "+tuiLine(string(data)))
	}
	if len(s.ProbeExits) > 0 {
		data, _ := json.Marshal(s.ProbeExits)
		lines = append(lines, "退出确认  "+tuiLine(string(data)))
	}
	if len(s.ProbeTransports) > 0 {
		data, _ := json.Marshal(s.ProbeTransports)
		lines = append(lines, "探针传输  "+tuiLine(string(data)))
	}
	if s.ProbeFailures > 0 {
		lines = append(lines, fmt.Sprintf("探针传输失败  %d 次（恢复后仍保留）", s.ProbeFailures))
	}
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
	fmt.Fprintf(&b, "%s%s  stream ID %d\n", label("协议"), tuiLine(t.Protocol), t.StreamID)
	fmt.Fprintf(&b, "%s%s\n", label("完整性原因"), tuiLine(strings.Join(t.IntegrityReasons, ", ")))
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
			b.WriteString(m.highlightBody(cleanTUIText(session.SafeText(t.Request))))
		}
	case 1:
		if len(t.Response) == 0 {
			b.WriteString("暂无响应内容")
		} else {
			b.WriteString(m.highlightBody(cleanTUIText(session.SafeText(t.Response))))
		}
	case 2:
		body, view := session.DecodedBody(t.Request, 1<<20)
		if view == "" {
			b.WriteString("暂无可用的 gzip 解码正文，请查看请求标签")
		} else {
			fmt.Fprintf(&b, "解码视图 %s\n\n%s", tuiLine(view), m.highlightBody(cleanTUIText(body)))
		}
	case 3:
		if len(t.Alerts) == 0 {
			b.WriteString("暂无告警")
		}
		request, response := cleanTUIText(session.SafeText(t.Request)), cleanTUIText(session.SafeText(t.Response))
		search := m.searchPattern()
		for _, a := range t.Alerts {
			match := cleanTUIText(a.Match)
			fmt.Fprintf(&b, "%s  %s\n%s\n%s\n%s\n%s\n\n", tuiSeverityStyle(a.Severity).Bold(true).Render(tuiLine(a.Rule)), tuiMuted.Render(fmt.Sprintf("版本 %d · 级别 %s · 字段 %s", a.Version, tuiSeverity(a.Severity), tuiLine(a.Field))), tuiMuted.Render(fmt.Sprintf("视图 %s · 解码 %d 轮", alertView(a.View), a.Decoding)), tuiMuted.Render("匹配片段"), tuiHighlight(match, tuiPattern([]string{match}), search), tuiMuted.Render(tuiOccurrences(a.Match, request, response)))
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
	if f.Until != "" {
		if t, err := time.Parse(indexTimeFormat, f.Until); err == nil {
			chips = append(chips, "[时间 ≤ "+t.Local().Format("01-02 15:04:05")+"]")
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
	} else if m.aggView() {
		line += tuiMuted.Render("  · x 清空")
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
	if m.searchInput != nil {
		return m.searchInput.View()
	}
	if m.flash != "" {
		return tuiAccent.Render(tuiLine(m.flash))
	}
	if notice := m.searchNotice(); notice != "" {
		return notice
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
	case m.searchInput != nil:
		return "输入后按 Enter 查找 · Esc 取消"
	case m.form != nil:
		return "Tab/↑↓ 换行 · ←→ 选项 · Enter 应用 · Ctrl+R 清空 · Esc 取消"
	case m.export != nil:
		return "Enter 导出 · Esc 取消"
	case m.help:
		return "? 或 Esc 关闭帮助 · q 退出"
	case m.details:
		return "↑↓ 滚动 · J/K 上下一条 · Tab 切标签 · / 查找 · c/m/H 按此筛选 · e 导出 · y 复制 ID · Esc 返回"
	case m.aggView():
		return "↑↓ 选择 · Enter 查看逐条 · v 切换视图 · / 筛选 · x 清空 · 空格 暂停 · s 会话 · ? 帮助"
	case m.tab == tabOverview:
		return "Tab 切换区块 · ↑↓ 选择 · Enter 跳到对应告警 · / 筛选 · 空格 暂停 · s 会话 · ? 帮助 · q 退出"
	case m.listTab() && m.drill != nil:
		return "Esc 返回上一层 · ↑↓ 选择 · Enter 详情 · c/m/H 按选中行筛选 · x 清空 · e 导出 · v 切换视图 · ? 帮助"
	case m.listTab():
		return "↑↓ 选择 · Enter 详情 · / 筛选 · c/m/H 按选中行筛选 · x 清空 · e 导出 · y 复制 ID · g 最新 · 空格 暂停 · s 会话 · ? 帮助"
	}
	return "1-4 切换页面 · ↑↓ 滚动 · / 筛选 · 空格 暂停 · r 刷新 · s 会话 · ? 帮助 · q 退出"
}

const tuiHelpText = `快捷键

页面    1 概览   2 请求   3 告警   4 采集健康   s 回到会话选择
概览    Tab 切换区块，Enter 把规则、来源或级别作为条件跳到告警列表
告警    v 在按规则、按来源、逐条三种视图间切换，聚合行上 Enter 查看逐条
移动    ↑↓ / j k 选择或滚动    g 回到最新并恢复跟随    G 本页末尾
        n p / ← → / PgDn PgUp 翻页
层级    Enter 打开详情或下钻    Esc 关闭弹层、关闭详情、退出下钻
详情    Tab / Shift+Tab 切换请求、响应、解码正文、检测依据
        J / K 不退出详情查看下一条、上一条
        / 在当前标签中查找，n / N 跳到下一处、上一处，Esc 清除
        告警匹配片段在请求、响应和解码正文中反色高亮
筛选    / 打开筛选面板    x 清空全部筛选
        c 只看选中行的客户端    m 只看它命中的规则    H 只看它的 Host
        再按一次同一个键取消该条件
证据    e 导出选中请求的证据压缩包（需要先停止采集）    y 复制请求 ID
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
	case m.tab == tabOverview && !m.details:
		content = m.overviewView(width, contentHeight)
	case m.tab == tabAlerts && !m.details:
		content = m.alertsView(width, contentHeight)
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
