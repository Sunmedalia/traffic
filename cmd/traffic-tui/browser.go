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
	path                    textinput.Model
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
		return fmt.Errorf("TUI 需要交互式终端，请在终端运行 traffic-tui")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := textinput.New()
	input.SetVirtualCursor(true)
	input.CharLimit = 4096
	input.SetWidth(74)
	m := &sessionBrowser{ctx: ctx, roots: sessionRoots(root), refresh: refresh, filter: filter, width: 80, height: 24, path: input}
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
	m.child = &tuiModel{ctx: ctx, store: s, refresh: m.refresh, filter: m.filter, snapshot: snapshot, width: m.width, height: m.height, viewport: viewport.New()}
	m.child.resize()
	return nil
}

// Tag every child command, including batches and ticks, so results from a closed
// session cannot update the next session or start duplicate refresh loops.
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
		if _, ok := msg.(tea.QuitMsg); ok {
			return msg
		}
		return sessionChildMsg{generation, msg}
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
		selectedDir := ""
		if m.selected < len(m.entries) {
			selectedDir = m.entries[m.selected].Dir
		}
		m.entries, m.notice, m.scanning = msg.Entries, msg.Warning, false
		m.selected = 0
		for i, entry := range m.entries {
			if entry.Dir == selectedDir {
				m.selected = i
			}
		}
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
			if key == "s" && !m.child.filtering {
				m.closeSession()
				return m, m.scan()
			}
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
			case "up", "k":
				m.selected = max(0, m.selected-1)
			case "down", "j":
				m.selected = min(max(0, len(m.entries)-1), m.selected+1)
			case "g", "home":
				m.selected = 0
			case "G", "end":
				m.selected = max(0, len(m.entries)-1)
			case "pgdown":
				m.selected = min(max(0, len(m.entries)-1), m.selected+max(1, (m.height-10)/2))
			case "pgup":
				m.selected = max(0, m.selected-max(1, (m.height-10)/2))
			case "enter":
				if m.scanning {
					return m, nil
				}
				if m.selected < len(m.entries) {
					entry := m.entries[m.selected]
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
func (m *sessionBrowser) View() tea.View {
	if m.child != nil {
		return m.child.View()
	}
	width, height := max(1, m.width), max(1, m.height)
	clip := func(s string) string { return termansi.Truncate(tuiLine(s), max(1, width-2), "…") }
	header := tuiAccent.Render("TRAFFIC  /  选择会话")
	count := fmt.Sprintf("%d 个会话 · 按开始时间从新到旧", len(m.entries))
	if m.scanning {
		count = "正在识别会话…"
	}
	lines := []string{header, tuiMuted.Render(clip(count)), tuiMuted.Render(clip("目录  " + strings.Join(m.roots, " · "))), ""}
	visible := max(1, (height-10)/2)
	start := max(0, m.selected-visible+1)
	for i := start; i < min(len(m.entries), start+visible); i++ {
		entry := m.entries[i]
		state := tuiState(entry.Stats.State)
		if entry.Problem != "" {
			state = "索引不可用"
		}
		counts := "请求 未知 · 告警 未知"
		if entry.CountsKnown {
			counts = fmt.Sprintf("请求 %d · 告警 %d", entry.Stats.Transactions, entry.Stats.Alerts)
		}
		label := fmt.Sprintf("%s  %s  %s  %s", entry.Started.Local().Format("2006-01-02 15:04:05"), tuiLine(entry.Name), state, counts)
		label = clip(label)
		if i == m.selected {
			label = tuiSelected.Render(label)
		}
		lines = append(lines, label, tuiMuted.Render(clip("  "+tuiLine(entry.Dir))))
	}
	if len(m.entries) == 0 && !m.scanning {
		lines = append(lines, "暂无会话，按 o 选择采集目录或 index.sqlite 文件")
	}
	body := lipgloss.NewStyle().Height(max(1, height-4)).Render(strings.Join(lines, "\n"))
	footer := "↑↓ 选择 · Enter 打开 · o 选择目录/文件 · r 重新扫描 · q 退出"
	if m.editing {
		body = tuiAccent.Render("选择会话位置") + "\n\n会话目录 / index.sqlite / 采集根目录\n\n" + m.path.View()
		footer = "Enter 识别会话 · Esc 取消"
	}
	frame := body + "\n" + tuiDanger.Render(clip(tuiLine(m.notice))) + "\n" + tuiMuted.Render(clip(footer))
	if width < 40 || height < 12 {
		frame = "终端过小，请调整到至少 40 列 × 12 行\nCtrl+C 退出"
	}
	view := tea.NewView(lipgloss.NewStyle().MaxWidth(width).MaxHeight(height).Render(frame))
	view.AltScreen = true
	return view
}
