package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	termansi "github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"
)

type sessionEntry struct {
	Dir, Name, Host, Problem string
	Started                  time.Time
	Stats                    Stats
	CountsKnown              bool
}
type sessionsFound struct {
	Entries []sessionEntry
	Warning string
}
type sessionChildMsg struct {
	Generation uint64
	Message    tea.Msg
}
type sessionBrowser struct {
	ctx                     context.Context
	roots                   []string
	entries                 []sessionEntry
	selected, width, height int
	scanning, editing       bool
	searching               bool
	path, query             textinput.Model
	order                   []int
	lastDir                 string
	notice                  string
	child                   *tuiModel
	childCancel             context.CancelFunc
	generation              uint64
	refresh                 time.Duration
	filter                  tuiFilter
}

func sessionPath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
		}
	}
	if filepath.Base(path) == "index.sqlite" {
		path = filepath.Dir(path)
	}
	absolute, err := filepath.Abs(path)
	if err == nil {
		return absolute
	}
	return filepath.Clean(path)
}

func sessionRoots(root string) []string {
	if root != "" {
		return []string{sessionPath(root)}
	}
	roots := []string{sessionPath("sessions")}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		base := filepath.Dir(exe)
		if filepath.Base(base) == "bin" {
			base = filepath.Dir(base)
		}
		candidate := filepath.Join(base, "sessions")
		if candidate != roots[0] {
			roots = append(roots, candidate)
		}
	}
	// Also recognize a session when started inside its directory.
	if info, err := os.Stat("index.sqlite"); err == nil && info.Mode().IsRegular() {
		roots = append(roots, sessionPath("."))
	}
	return roots
}

func discoverSessions(ctx context.Context, roots []string) sessionsFound {
	result := sessionsFound{}
	seen := map[string]bool{}
	warnings := []string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if walkErr != nil {
				if !os.IsNotExist(walkErr) {
					warnings = append(warnings, walkErr.Error())
				}
				return nil
			}
			if entry.IsDir() || entry.Name() != "index.sqlite" || !entry.Type().IsRegular() {
				return nil
			}
			dir := filepath.Dir(path)
			if seen[dir] {
				return nil
			}
			seen[dir] = true
			item := sessionEntry{Dir: dir, Name: filepath.Base(dir)}
			var manifest struct {
				Name    string    `json:"name"`
				Host    string    `json:"hostname"`
				Started time.Time `json:"started"`
			}
			if b, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err == nil {
				if json.Unmarshal(b, &manifest) == nil {
					if manifest.Name != "" {
						item.Name = manifest.Name
					}
					item.Host, item.Started = manifest.Host, manifest.Started
				}
			}
			var statusWarning string
			item.Stats, statusWarning = readTUIStatus(dir)
			item.CountsKnown = statusWarning == "" || item.Stats.State == "stale"
			if item.Started.IsZero() {
				item.Started = item.Stats.Started
			}
			if item.Started.IsZero() {
				if info, err := entry.Info(); err == nil {
					item.Started = info.ModTime()
				}
			}
			s, err := openStore(dir)
			if err == nil {
				checkCtx, cancel := context.WithTimeout(ctx, time.Second)
				// Validate the schema, even for an empty or legacy session without a manifest.
				rows, queryErr := s.db.QueryContext(checkCtx, "SELECT id,time,client,alert,data FROM requests LIMIT 0")
				if rows != nil {
					rows.Close()
				}
				cancel()
				s.db.Close()
				err = queryErr
			}
			if err != nil {
				item.Problem = err.Error()
			}
			result.Entries = append(result.Entries, item)
			return nil
		})
		if err != nil {
			warnings = append(warnings, err.Error())
		}
	}
	sort.Slice(result.Entries, func(i, j int) bool {
		if result.Entries[i].Started.Equal(result.Entries[j].Started) {
			return result.Entries[i].Dir < result.Entries[j].Dir
		}
		return result.Entries[i].Started.After(result.Entries[j].Started)
	})
	result.Warning = strings.Join(warnings, " · ")
	return result
}

func runSessionBrowser(dir, root string, refresh time.Duration, filter tuiFilter) error {
	if refresh <= 0 {
		return fmt.Errorf("--refresh 必须大于 0")
	}
	if !term.IsTerminal(os.Stdin.Fd()) || !term.IsTerminal(os.Stdout.Fd()) {
		return fmt.Errorf("TUI 需要交互式终端，请在终端运行 traffic-console")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := textinput.New()
	input.SetVirtualCursor(true)
	input.CharLimit = 4096
	input.SetWidth(74)
	m := &sessionBrowser{ctx: ctx, roots: sessionRoots(root), refresh: refresh, filter: filter, width: 80, height: 24, path: input, query: newSessionQuery()}
	defer m.closeSession()
	if dir != "" {
		m.roots = append(m.roots, sessionPath(dir))
		if err := m.openSession(sessionPath(dir)); err != nil {
			return err
		}
	}
	_, err := tea.NewProgram(m, tea.WithContext(ctx)).Run()
	return err
}
func (m *sessionBrowser) closeSession() {
	if m.childCancel != nil {
		m.childCancel()
		m.childCancel = nil
	}
	if m.child != nil {
		m.child.store.db.Close()
		m.child = nil
	}
	m.generation++
}
func (m *sessionBrowser) openSession(dir string) error {
	s, err := openStore(dir)
	if err != nil {
		return fmt.Errorf("无法打开会话: %w", err)
	}
	ctx, cancel := context.WithCancel(m.ctx)
	checkCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	snapshot, err := loadTUISnapshot(checkCtx, s, m.filter, false, 0, "", nil)
	stop()
	if err != nil {
		cancel()
		s.db.Close()
		return fmt.Errorf("无法读取会话: %w", err)
	}
	m.closeSession()
	m.childCancel = cancel
	m.lastDir = dir
	m.child = &tuiModel{ctx: ctx, store: s, refresh: m.refresh, filter: m.filter, snapshot: snapshot, title: sessionTitle(dir), width: m.width, height: m.height, viewport: viewport.New()}
	m.child.resize()
	return nil
}

// Tag the child's session results, including those inside batches, so results from
// a closed session cannot update the next session or start duplicate refresh loops.
func sessionCommand(cmd tea.Cmd, generation uint64) tea.Cmd {
	if cmd == nil {
		return nil
	}
	return func() tea.Msg {
		msg := cmd()
		if batch, ok := msg.(tea.BatchMsg); ok {
			commands := make([]tea.Cmd, len(batch))
			for i, child := range batch {
				commands[i] = sessionCommand(child, generation)
			}
			return tea.Batch(commands...)()
		}
		// Only session data needs the tag. Runtime messages such as clipboard
		// writes must reach Bubble Tea itself; input widgets accept them untagged.
		switch msg.(type) {
		case tuiTick, tuiLoaded, tuiExported:
			return sessionChildMsg{generation, msg}
		}
		return msg
	}
}
func (m *sessionBrowser) scan() tea.Cmd {
	if m.scanning {
		return nil
	}
	m.scanning = true
	roots := append([]string(nil), m.roots...)
	return func() tea.Msg { return discoverSessions(m.ctx, roots) }
}
func (m *sessionBrowser) Init() tea.Cmd {
	if m.child != nil {
		return sessionCommand(m.child.Init(), m.generation)
	}
	return m.scan()
}
func (m *sessionBrowser) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.path.SetWidth(max(1, msg.Width-6))
	case sessionsFound:
		selectedDir := m.lastDir
		if entry, ok := m.current(); ok {
			selectedDir = entry.Dir
		}
		m.entries, m.notice, m.scanning = msg.Entries, msg.Warning, false
		m.reorder(selectedDir)
		return m, nil
	case sessionChildMsg:
		if m.child == nil || msg.Generation != m.generation {
			return m, nil
		}
		_, cmd := m.child.Update(msg.Message)
		return m, sessionCommand(cmd, m.generation)
	case tea.KeyPressMsg:
		key := msg.String()
		if key == "ctrl+c" {
			return m, tea.Quit
		}
		if m.child != nil {
			if key == "s" && !m.child.modal() {
				m.closeSession()
				return m, m.scan()
			}
		} else if m.searching {
			switch key {
			case "esc":
				m.query.SetValue("")
				fallthrough
			case "enter":
				m.searching = false
				m.query.Blur()
				m.reorder(m.selectedDir())
				return m, nil
			case "up", "down":
				m.move(map[string]int{"up": -1, "down": 1}[key])
				return m, nil
			}
			var cmd tea.Cmd
			m.query, cmd = m.query.Update(msg)
			m.reorder(m.selectedDir())
			return m, cmd
		} else if m.editing {
			switch key {
			case "esc":
				m.editing = false
				m.path.Blur()
				return m, nil
			case "enter":
				value := strings.TrimSpace(m.path.Value())
				if value == "" {
					m.notice = "请输入会话目录、索引文件或采集根目录"
					return m, nil
				}
				if m.scanning {
					return m, nil
				}
				m.roots = []string{sessionPath(value)}
				m.editing = false
				m.path.Blur()
				return m, m.scan()
			}
		} else {
			switch key {
			case "q":
				return m, tea.Quit
			case "r":
				return m, m.scan()
			case "o":
				m.editing = true
				m.path.SetWidth(max(1, m.width-6))
				m.path.SetValue(m.roots[0])
				return m, m.path.Focus()
			case "/":
				m.searching = true
				m.query.SetWidth(max(1, m.width-8))
				return m, m.query.Focus()
			case "esc":
				if m.query.Value() != "" {
					m.query.SetValue("")
					m.reorder(m.selectedDir())
				}
			case "up", "k":
				m.move(-1)
			case "down", "j":
				m.move(1)
			case "g", "home":
				m.selected = 0
			case "G", "end":
				m.selected = max(0, len(m.order)-1)
			case "pgdown":
				m.move(max(1, (m.height-10)/2))
			case "pgup":
				m.move(-max(1, (m.height-10)/2))
			case "enter":
				if m.scanning {
					return m, nil
				}
				if entry, ok := m.current(); ok {
					if entry.Problem != "" {
						m.notice = "会话索引不可用 · " + entry.Problem
						return m, nil
					}
					if err := m.openSession(entry.Dir); err != nil {
						m.notice = err.Error()
						return m, nil
					}
					return m, sessionCommand(m.child.Init(), m.generation)
				}
			}
			return m, nil
		}
	}
	if m.child != nil {
		_, cmd := m.child.Update(msg)
		return m, sessionCommand(cmd, m.generation)
	}
	if m.editing {
		var cmd tea.Cmd
		m.path, cmd = m.path.Update(msg)
		return m, cmd
	}
	return m, nil
}
func newSessionQuery() textinput.Model {
	query := textinput.New()
	query.SetVirtualCursor(true)
	query.CharLimit = 256
	query.Placeholder = "会话名、主机或路径"
	return query
}

// sessionTitle names a session as host / date / name for the workspace header.
func sessionTitle(dir string) string {
	var manifest struct {
		Name    string    `json:"name"`
		Host    string    `json:"hostname"`
		Started time.Time `json:"started"`
	}
	parts := []string{}
	if b, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err == nil && json.Unmarshal(b, &manifest) == nil {
		if manifest.Host != "" {
			parts = append(parts, manifest.Host)
		}
		if !manifest.Started.IsZero() {
			parts = append(parts, manifest.Started.Local().Format("2006-01-02"))
		}
	}
	name := manifest.Name
	if name == "" {
		name = filepath.Base(dir)
	}
	return strings.Join(append(parts, name), " / ")
}

func sessionHost(entry sessionEntry) string {
	if entry.Host == "" {
		return "未知主机"
	}
	return entry.Host
}

// reorder applies the search and groups sessions by host. Hosts follow their newest
// session, and live captures come first within a host.
func (m *sessionBrowser) reorder(selectedDir string) {
	query := strings.ToLower(strings.TrimSpace(m.query.Value()))
	hostRank := map[string]int{}
	m.order = m.order[:0]
	for i, entry := range m.entries {
		if query != "" && !strings.Contains(strings.ToLower(entry.Name+" "+entry.Host+" "+entry.Dir), query) {
			continue
		}
		if _, ok := hostRank[sessionHost(entry)]; !ok {
			hostRank[sessionHost(entry)] = len(hostRank)
		}
		m.order = append(m.order, i)
	}
	sort.SliceStable(m.order, func(a, b int) bool {
		x, y := m.entries[m.order[a]], m.entries[m.order[b]]
		if hostRank[sessionHost(x)] != hostRank[sessionHost(y)] {
			return hostRank[sessionHost(x)] < hostRank[sessionHost(y)]
		}
		return x.Stats.State == "running" && y.Stats.State != "running"
	})
	m.selected = 0
	for i, index := range m.order {
		if m.entries[index].Dir == selectedDir {
			m.selected = i
		}
	}
}
func (m *sessionBrowser) current() (sessionEntry, bool) {
	if m.selected < len(m.order) && m.order[m.selected] < len(m.entries) {
		return m.entries[m.order[m.selected]], true
	}
	return sessionEntry{}, false
}
func (m *sessionBrowser) selectedDir() string {
	entry, _ := m.current()
	return entry.Dir
}
func (m *sessionBrowser) move(step int) {
	m.selected = max(0, min(len(m.order)-1, m.selected+step))
}

func sessionBadge(entry sessionEntry) string {
	if entry.Problem != "" {
		return tuiDanger.Render("✕ 索引不可用")
	}
	return tuiStateBadge(entry.Stats.State)
}

func (m *sessionBrowser) View() tea.View {
	if m.child != nil {
		return m.child.View()
	}
	width, height := max(1, m.width), max(1, m.height)
	clip := func(s string) string { return termansi.Truncate(s, width, "…") }
	running := 0
	for _, entry := range m.entries {
		if entry.Stats.State == "running" {
			running++
		}
	}
	count := fmt.Sprintf("%d 个会话", len(m.entries))
	if running > 0 {
		count += fmt.Sprintf(" · %d 个正在采集", running)
	}
	if len(m.order) != len(m.entries) {
		count = fmt.Sprintf("显示 %d / %d 个会话", len(m.order), len(m.entries))
	}
	if m.scanning {
		count = "正在识别会话…"
	}
	header := []string{tuiSpread(tuiAccent.Render("TRAFFIC  /  选择会话"), tuiMuted.Render(count), width), tuiMuted.Render(clip(tuiLine("目录  " + strings.Join(m.roots, " · "))))}
	if m.searching || m.query.Value() != "" {
		search := tuiMuted.Render("查找  ") + tuiLine(m.query.Value())
		if m.searching {
			search = tuiMuted.Render("查找  ") + m.query.View()
		}
		header = append(header, clip(search))
	}
	header = append(header, "")

	// Build every row, then show the window that keeps the cursor visible.
	numbers := width >= 70
	columns := tuiCell("", 2) + tuiCell("状态", 14) + tuiCell("开始时间", 16)
	if numbers {
		columns += tuiCell("请求", 10) + tuiCell("告警", 8)
	}
	rows := []string{}
	cursor := 0
	lastHost := ""
	for i, index := range m.order {
		entry := m.entries[index]
		if host := sessionHost(entry); i == 0 || host != lastHost {
			rows = append(rows, tuiAccent.Render(clip(tuiLine(host))))
			lastHost = host
		}
		requests, alerts := tuiMuted.Render(tuiCell("未知", 10)), tuiMuted.Render(tuiCell("未知", 8))
		if entry.CountsKnown {
			requests = tuiCell(tuiCount(entry.Stats.Transactions), 10)
			alerts = tuiCell(tuiCount(entry.Stats.Alerts), 8)
			if entry.Stats.Alerts > 0 {
				alerts = tuiDanger.Render(alerts)
			}
		}
		if i == m.selected {
			cursor = len(rows)
			plain := tuiCell("", 2) + tuiCell(termansi.Strip(sessionBadge(entry)), 14) + tuiCell(entry.Started.Local().Format("01-02 15:04:05"), 16)
			if numbers {
				plain += termansi.Strip(requests) + termansi.Strip(alerts)
			}
			plain += tuiLine(entry.Name)
			rows = append(rows, tuiSelected.Render(tuiCell(plain, width)))
			continue
		}
		line := tuiCell("", 2) + tuiCell(sessionBadge(entry), 14) + tuiCell(entry.Started.Local().Format("01-02 15:04:05"), 16)
		if numbers {
			line += requests + alerts
		}
		rows = append(rows, clip(line+tuiLine(entry.Name)))
	}
	if len(m.order) == 0 && !m.scanning {
		if len(m.entries) > 0 {
			rows = append(rows, "没有匹配的会话，按 Esc 清除查找")
		} else {
			rows = append(rows, "暂无会话，按 o 选择采集目录或 index.sqlite 文件")
		}
	}
	visible := max(1, height-len(header)-5)
	start := max(0, cursor-visible+1)
	end := min(len(rows), start+visible)
	body := append(append(header, tuiMuted.Render(clip(columns+"会话"))), rows[start:end]...)
	path := ""
	if entry, ok := m.current(); ok {
		path = entry.Dir
	}
	footer := "↑↓ 选择 · Enter 打开 · / 查找 · o 指定目录或文件 · r 重新扫描 · q 退出"
	if m.searching {
		footer = "输入即筛选 · ↑↓ 选择 · Enter 完成 · Esc 清除"
	}
	content := lipgloss.NewStyle().Height(max(1, height-3)).MaxHeight(max(1, height-3)).Render(strings.Join(body, "\n"))
	if m.editing {
		content = lipgloss.NewStyle().Height(max(1, height-3)).Render(tuiAccent.Render("选择会话位置") + "\n\n会话目录 / index.sqlite / 采集根目录\n\n" + m.path.View())
		footer = "Enter 识别会话 · Esc 取消"
		path = ""
	}
	frame := content + "\n" + tuiMuted.Render(clip(tuiLine(path))) + "\n" + tuiDanger.Render(clip(tuiLine(m.notice))) + "\n" + tuiMuted.Render(clip(footer))
	if width < 40 || height < 12 {
		frame = "终端过小，请调整到至少 40 列 × 12 行\nCtrl+C 退出"
	}
	view := tea.NewView(lipgloss.NewStyle().MaxWidth(width).MaxHeight(height).Render(frame))
	view.AltScreen = true
	return view
}
