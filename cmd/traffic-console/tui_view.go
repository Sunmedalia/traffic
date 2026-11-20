package main

// Rendering of the TUI pages: health, list, detail and chrome lines.

import (
	"bytes"
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
	return tuiIn(s.Started).Format("2006-01-02 15:04:05 MST -07:00")
}
func (m tuiModel) stoppedText() string {
	s := m.snapshot.Stats
	text := "—"
	if !s.Stopped.IsZero() {
		text = tuiFormatTime(s.Stopped, "")
	}
	if s.StopReason != "" {
		text += " · " + tuiLine(s.StopReason)
	}
	return text
}
func (m tuiModel) dirText() string {
	if m.store == nil {
		return "—"
	}
	return tuiLine(m.store.dir)
}
func (m tuiModel) lastPacketText() string {
	if t := m.snapshot.Stats.LastPacketAt; !t.IsZero() {
		return tuiIn(t).Format("2006-01-02 15:04:05.000")
	}
	return "—"
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
		label("停止")+m.stoppedText(),
		label("最后收包")+m.lastPacketText(),
		label("会话目录")+m.dirText(),
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

// cacheBodies decodes the open record's bodies once per record version.
func (m *tuiModel) cacheBodies() {
	t := m.snapshot.Detail
	if t == nil || t.ID != m.detailID {
		return
	}
	key := fmt.Sprintf("%s|%d|%d|%d", t.ID, len(t.Request), len(t.Response), t.Status)
	if m.bodies.key == key {
		return
	}
	m.bodies = tuiBodies{key: key}
	m.bodies.request, m.bodies.requestView = session.DecodedBody(t.Request, 1<<20)
	m.bodies.response, m.bodies.responseView = session.DecodedBody(t.Response, 1<<20)
}
func (m tuiModel) requestText() string  { return session.SafeText(m.snapshot.Detail.Request) }
func (m tuiModel) responseText() string { return session.SafeText(m.snapshot.Detail.Response) }

// prettyBody indents JSON bodies unless the raw view is selected.
func (m tuiModel) prettyBody(body string) string {
	trimmed := strings.TrimSpace(body)
	if m.raw || trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return body
	}
	var out bytes.Buffer
	if json.Indent(&out, []byte(trimmed), "", "  ") != nil {
		return body
	}
	return out.String()
}

// httpView prints a message with styled header names and an optional JSON indent.
func (m tuiModel) httpView(text string) string {
	message := tuiSplitHTTP(cleanTUIText(text))
	var b strings.Builder
	b.WriteString(tuiBold.Render(m.highlightBody(message.start)) + "\n")
	for _, h := range message.headers {
		if h[1] == "\x00" {
			b.WriteString(m.highlightBody(h[0]) + "\n")
			continue
		}
		b.WriteString(tuiAccent.UnsetBold().Render(h[0]) + ": " + m.highlightBody(h[1]) + "\n")
	}
	if message.body != "" {
		b.WriteString("\n" + m.highlightBody(m.prettyBody(message.body)))
	}
	return b.String()
}

func (m tuiModel) paramsBlock(title string, pairs [][2]string) string {
	if len(pairs) == 0 {
		return ""
	}
	width := 8
	for _, p := range pairs {
		width = max(width, min(24, lipgloss.Width(tuiLine(p[0]))+2))
	}
	lines := []string{"\n", tuiBold.Render(title) + tuiMuted.Render("  d 后用 ←→ 选择可解码的参数")}
	for _, p := range pairs[:min(len(pairs), 200)] {
		lines = append(lines, tuiAccent.UnsetBold().Render(tuiCell(tuiLine(p[0]), width))+m.highlightBody(tuiLine(p[1])))
	}
	return strings.Join(lines, "\n")
}

func (m tuiModel) detailContent() string {
	if m.snapshot.DetailMissing {
		return "这条记录已被保留期清理，无法再查看。按 Esc 返回列表，或按 j/k 查看相邻记录"
	}
	t := m.snapshot.Detail
	if t == nil || t.ID != m.detailID {
		return "正在加载详情…"
	}
	var b strings.Builder
	label := func(s string) string { return tuiMuted.Render(tuiCell(s, 16)) }
	status := tuiStatusStyle(t.Status).Render(fmt.Sprint(t.Status))
	if t.Status == 0 {
		status = tuiMuted.Render("待响应")
	}
	pills := []string{tuiBold.Render(tuiLine(t.Method)), status}
	if t.Incomplete {
		pills = append(pills, tuiWarn.Render("[不完整]"))
	}
	if t.Truncated {
		pills = append(pills, tuiWarn.Render("[截断]"))
	}
	seen := map[string]bool{}
	for _, a := range t.Alerts {
		if !seen[a.Rule] && len(seen) < 4 {
			seen[a.Rule] = true
			pills = append(pills, tuiSeverityStyle(a.Severity).Bold(true).Render("["+tuiLine(a.Rule)+"]"))
		}
	}
	b.WriteString(strings.Join(pills, " ") + "\n")
	b.WriteString(tuiMuted.Render(tuiLine(t.Host)) + " " + m.highlightBody(tuiLine(t.URL)) + "\n")
	when := tuiIn(t.Time).Format("2006-01-02 15:04:05.000")
	if !m.metaOpen {
		summary := []string{when, tuiLine(t.Client)}
		if t.Service != "" {
			summary = append(summary, tuiLine(t.Service))
		}
		if t.Protocol != "" {
			summary = append(summary, tuiLine(t.Protocol))
		}
		if t.StreamID != 0 {
			summary = append(summary, fmt.Sprintf("stream ID %d", t.StreamID))
		}
		line := tuiMuted.Render(strings.Join(summary, " · "))
		// Integrity reasons stay visible: they qualify everything shown below.
		if len(t.IntegrityReasons) > 0 {
			line += tuiWarn.Render(" · 完整性原因 " + tuiLine(strings.Join(t.IntegrityReasons, ", ")))
		}
		b.WriteString(line + tuiMuted.Render("  · i 展开记录信息") + "\n")
	} else {
		service := tuiLine(t.Service)
		if t.TargetID != "" {
			service += " · " + tuiLine(t.TargetID)
		}
		endpoints := []string{}
		for _, part := range []string{t.Backend, t.LocalEndpoint} {
			if part != "" {
				endpoints = append(endpoints, tuiLine(part))
			}
		}
		source := []string{}
		if t.Source != "" {
			source = append(source, tuiLine(t.Source))
		}
		if t.PID != 0 {
			source = append(source, fmt.Sprintf("PID %d", t.PID))
		}
		protocol := tuiLine(t.Protocol)
		if protocol == "" {
			protocol = "未知"
		}
		stream := ""
		if t.StreamID != 0 {
			stream = fmt.Sprint(t.StreamID)
		}
		rows := [][2]string{
			{"时间", when}, {"来源", tuiLine(t.Client) + tuiMuted.Render("  c 按来源筛选")}, {"直连对端", tuiLine(t.PeerClient)}, {"来源地址依据", tuiLine(t.ClientSource)},
			{"Host", tuiLine(t.Host) + tuiMuted.Render("  H 按 Host 筛选")}, {"服务", service}, {"后端 / 本地端点", strings.Join(endpoints, " · ")},
			{"采集来源", strings.Join(source, " · ")}, {"连接", tuiLine(t.Connection)}, {"协议", protocol}, {"HTTP/2 stream ID", stream},
			{"完整性原因", tuiLine(strings.Join(t.IntegrityReasons, ", "))}, {"记录 ID", tuiLine(t.ID) + tuiMuted.Render("  y 复制")},
		}
		if t.Service != "" {
			rows[5][1] += tuiMuted.Render("  S 按服务筛选")
		}
		for _, row := range rows {
			if termansi.Strip(row[1]) != "" && !strings.HasPrefix(termansi.Strip(row[1]), "  ") {
				b.WriteString(label(row[0]) + row[1] + "\n")
			}
		}
		b.WriteString(tuiMuted.Render("i 收起记录信息") + "\n")
	}
	b.WriteString("\n")
	active := m.activeDetailTab()
	for _, tab := range m.detailTabs() {
		name := tuiDetailNames[tab]
		if tab == detailAlerts {
			name += fmt.Sprintf(" %d", len(t.Alerts))
		}
		if tab == active {
			b.WriteString(tuiAccent.Render("[" + name + "]"))
		} else {
			b.WriteString(tuiMuted.Render(name))
		}
		b.WriteString("  ")
	}
	format := "f 原文"
	if m.raw {
		format = "f 格式化 JSON"
	}
	b.WriteString(tuiMuted.Render(" [ ] 切换 · " + format + " · Y 复制"))
	b.WriteString("\n\n")
	switch active {
	case detailRequest:
		if len(t.Request) == 0 {
			b.WriteString("没有保存请求内容。")
			break
		}
		text := m.requestText()
		b.WriteString(m.httpView(text))
		message := tuiSplitHTTP(text)
		if strings.Contains(strings.ToLower(message.header("content-type")), "x-www-form-urlencoded") {
			b.WriteString(m.paramsBlock("表单参数（原文）", tuiPairs(message.body, tuiAmp)))
		}
		b.WriteString(m.paramsBlock("Cookie（原文）", tuiPairs(message.header("cookie"), tuiSemi)))
	case detailResponse:
		switch {
		case len(t.Response) > 0:
			b.WriteString(m.httpView(m.responseText()))
		case t.Status != 0:
			b.WriteString("没有保存响应内容。")
		default:
			b.WriteString("还没有采集到响应。会话仍在采集时，响应到达后会自动出现。")
		}
	case detailDecoder:
		b.WriteString(m.decoderContent())
	case detailDecoded:
		for _, part := range []struct{ title, view, body string }{{"请求正文", m.bodies.requestView, m.bodies.request}, {"响应正文", m.bodies.responseView, m.bodies.response}} {
			if part.view == "" {
				continue
			}
			fmt.Fprintf(&b, "%s\n%s\n\n", tuiBold.Render(part.title+" · "+tuiLine(part.view)), m.highlightBody(cleanTUIText(strings.ToValidUTF8(part.body, "\uFFFD"))))
		}
	case detailAlerts:
		request, response := cleanTUIText(m.requestText()), cleanTUIText(m.responseText())
		search := m.searchPattern()
		for _, a := range t.Alerts {
			match := cleanTUIText(a.Match)
			view := a.View
			if view == "" {
				view = "原始内容"
			}
			fmt.Fprintf(&b, "%s %s\n%s\n%s\n%s\n%s\n\n",
				tuiSeverityStyle(a.Severity).Bold(true).Render("["+tuiSeverity(a.Severity)+"]"), tuiBold.Render(tuiLine(a.Rule)),
				tuiMuted.Render(fmt.Sprintf("规则版本 %d · 命中字段 %s · 视图 %s · URL 解码 %d 轮", a.Version, tuiLine(a.Field), tuiLine(view), a.Decoding)),
				tuiHighlight(match, tuiPattern([]string{match}), search), tuiMuted.Render(tuiOccurrences(a.Match, request, response)),
				tuiMuted.Render("m 查看同规则请求 · d 解码片段"))
		}
	}
	return b.String()
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
	header := tuiCell("时间", timeWidth) + tuiCell("级", 3) + tuiCell("方法", 7) + tuiCell("状态", 7)
	if showClient {
		header += tuiCell("来源", clientWidth)
	}
	if showHost {
		header += tuiCell("Host", hostWidth)
	}
	lines := []string{}
	// The web list shows the filtered timeline above the table.
	if timeline := m.listTimeline(); timeline != nil && height >= 10 && !m.split() {
		lines = append(lines, m.timelineBars(timeline, width, 1, m.tab == tabAlerts, false)[0])
		height--
	}
	top := len(lines)
	lines = append(lines, tuiMuted.Render(termansi.Truncate(header+"URL", width, "…")))
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
			{tuiSeverity(r.Severity), 3, tuiSeverityStyle(r.Severity)},
			{tuiLine(r.Method), 7, lipgloss.NewStyle()},
			{status, 7, tuiStatusStyle(r.Status)},
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
	for len(lines)-top < height-1 {
		lines = append(lines, "")
	}
	pager := tuiMuted.Render(fmt.Sprintf("%s 条 · 第 %d / %d 页", tuiCount(uint64(m.snapshot.Count)), m.page+1, max(1, (m.snapshot.Count+99)/100)))
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
	add(f.Keyword, "关键词 ")
	if f.Decode > 0 {
		chips = append(chips, fmt.Sprintf("[URL 解码 %d 次后匹配]", f.Decode))
	}
	if f.Severity != "" {
		chips = append(chips, "[级别 ≥ "+tuiSeverity(f.Severity)+"]")
	}
	switch f.Status {
	case "":
	case "pending":
		chips = append(chips, "[状态 待响应]")
	default:
		add(f.Status, "状态 ")
	}
	add(f.Method, "方法 ")
	if f.HideStatic {
		chips = append(chips, "[隐藏静态资源]")
	}
	add(f.Exclude, "排除 ")
	add(f.Param, "参数 ")
	add(f.Client, "来源 ")
	add(f.Rule, "规则 ")
	add(f.Service, "服务 ")
	if f.Since != "" || f.Until != "" {
		bound := func(stamp, empty string) string {
			if stamp == "" {
				return empty
			}
			if t, err := time.Parse(indexTimeFormat, stamp); err == nil {
				return tuiIn(t).Format("01-02 15:04:05")
			}
			return tuiLine(stamp)
		}
		end := "≤ "
		if f.UntilExclusive {
			end = "< "
		}
		if f.Until == "" {
			end = ""
		}
		chips = append(chips, "[时间 "+bound(f.Since, "最早")+" – "+end+bound(f.Until, "最新")+"]")
	}
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
	right := tuiMuted.Render(fmt.Sprintf("请求 %s · 告警 %s", tuiCount(s.Transactions), tuiCount(s.Alerts)))
	if mode != "" {
		right += tuiMuted.Render(" · " + mode)
	}
	if m.analysisRunning() {
		right = tuiAccent.Render("● 分析中 "+tuiJobElapsed(m.analysis.job)) + tuiMuted.Render(" · ") + right
	}
	return tuiSpread(left, right, width)
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
	return tuiSpread(strings.Join(parts, "   "), tuiMuted.Render("时间 "+tuiZoneLabel()+" · z 切换"), width)
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
	case m.analysis != nil && m.analysis.open:
		return "↑↓ 选择规则 · Enter 开始分析 · x 停止分析 · Esc 关闭（任务在后台继续）"
	case m.searchInput != nil:
		return "输入后按 Enter 查找 · Esc 取消"
	case m.form != nil:
		return "Tab/↑↓ 换行 · ←→ 选项 · Enter 应用 · Ctrl+R 清空 · Esc 取消"
	case m.export != nil:
		return "Enter 导出 · Esc 取消"
	case m.help:
		return "? 或 Esc 关闭帮助 · q 退出"
	case m.details && m.decoder != nil && m.decoder.editor != nil:
		return "Enter 用输入内容替换原文 · Esc 取消"
	case m.details && m.decoder != nil && m.decoder.picking:
		return "↑↓ 选择解码方式 · Enter 解码 · Esc 取消"
	case m.details && m.activeDetailTab() == detailDecoder:
		return "←→ 换来源 · Enter 解码 · Backspace 撤销 · X 十六进制 · w 手动输入 · Y 复制结果 · [ ] 切标签 · Esc 返回"
	case m.details:
		return "j/k 上下一条 · ↑↓ 滚动 · [ ] 切标签 · d 解码 · f 格式化 · i 记录信息 · / 查找 · c/m/H/S 筛选 · e 导出 · Y 复制 · Esc 返回"
	case m.aggView():
		return "↑↓ 选择 · Enter 查看逐条 · v 切换视图 · / 筛选 · x 清空 · A 分析 · s 会话 · ? 帮助"
	case m.tab == tabOverview && m.block == blockTimeline:
		return "←→ 移动 · Shift+←→ 选范围 · Enter 查看这段请求 · Tab 切换区块 · A 分析 · r 刷新 · s 会话 · ? 帮助"
	case m.tab == tabOverview:
		return "Tab 切换区块 · ↑↓ 选择 · Enter 查看对应请求 · A 分析 · 空格 暂停 · r 刷新 · s 会话 · ? 帮助 · q 退出"
	case m.listTab() && m.drill != nil:
		return "Esc 返回上一层 · ↑↓ 选择 · Enter 详情 · c/m/H 按选中行筛选 · x 清空 · e 导出 · v 切换视图 · ? 帮助"
	case m.listTab():
		return "↑↓ 选择 · Enter 详情 · n/p 翻页 · / 筛选 · c/m/H 按选中行筛选 · x 清空 · e 导出 · g 最新 · 空格 暂停 · A 分析 · s 会话 · ? 帮助"
	}
	return "1-4 切换页面 · ↑↓ 滚动 · / 筛选 · 空格 暂停 · r 刷新 · A 分析 · s 会话 · ? 帮助 · q 退出"
}

const tuiHelpText = `快捷键（与网页版一致的键位优先）

页面    1 概览   2 请求   3 告警   4 采集健康   s 回到会话列表
概览    Tab 切换区块，Enter 查看对应请求：规则、级别 → 告警；来源、状态 → 请求
        时间线 ←→ 移动，Shift+←→ 选一段时间，Enter 查看这段时间的请求
告警    v 在逐条、按规则、按来源三种视图间切换，聚合行上 Enter 查看逐条
移动    ↑↓ / j k 选择    g 回到最新并恢复跟随    G 本页末尾
        n p / ← → / PgDn PgUp 翻页
层级    Enter 打开详情或下钻    Esc 关闭弹层、关闭详情、退出下钻
详情    j / k 下一条、上一条    ↑↓ PgUp PgDn 滚动    [ ] 或 Tab 切换标签
        标签：请求、响应、解码、解压正文、检测依据
        d 打开解码工具    f 切换 JSON 格式化    i 展开记录信息
        / 在当前标签中查找，n / N 跳到下一处、上一处，Esc 清除
        Y 复制当前标签内容    y 复制请求 ID
解码    ←→ 选择来源（URL、参数、Cookie、表单、请求头、命中片段）
        Enter 选择解码方式（URL、Base64、Hex、HTML、Unicode、JWT、Gzip），可连续解码
        Backspace 撤销一步    X 十六进制    w 手动输入
筛选    / 打开筛选面板：关键词、URL 解码匹配、级别、状态、方法、静态资源、
        排除词、参数、状态码、来源、规则、服务、时间范围    x 清空全部筛选
        c 来源    m 规则    H Host    S 服务（详情中）  再按一次同一个键取消
分析    A 打开分析面板，用内置规则或规则目录中的文件重新分析当前会话
证据    e 导出选中请求的证据压缩包（需要先停止采集）
刷新    光标在第一页第一行时跟随最新记录，离开后列表定格
        空格 暂停或恢复    r 立即刷新    z 切换本地时间 / UTC
退出    q 或 Ctrl+C`

func (m tuiModel) View() tea.View {
	width, height := max(1, m.width), max(1, m.height)
	contentHeight := m.contentHeight()
	content := m.viewport.View()
	switch {
	case m.help:
		content = tuiHelpText
	case m.analysis != nil && m.analysis.open:
		content = m.analysisView(contentHeight)
	case m.form != nil:
		content = m.form.view(contentHeight)
	case m.export != nil:
		content = m.export.view()
	case m.split():
		listWidth := width / 2
		content = lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(listWidth).Render(m.listView(listWidth-1, contentHeight)), tuiMuted.Render(strings.TrimSuffix(strings.Repeat(" │ \n", contentHeight), "\n")), m.viewport.View())
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
