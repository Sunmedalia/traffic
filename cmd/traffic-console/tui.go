package main

import (
	lipgloss "charm.land/lipgloss/v2"
	"context"
	"fmt"
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"
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
	Version    uint64
	Snapshot   tuiSnapshot
	Err        error
	Summary    *tuiSummary
	SummaryKey string
}

// Alert tab views and overview blocks.
const (
	viewRules = iota
	viewSources
	viewList
	alertViewCount
)
const (
	blockLevels = iota
	blockRules
	blockSources
	blockRecent
	blockCount
)

// Summaries scan alert bodies, so they refresh less often than the list.
const tuiSummaryInterval = 5 * time.Second

// tuiDrill remembers where a drill-down started so Esc can return there.
type tuiDrill struct {
	tab, view, selected int
	filter              tuiFilter
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
	alertView                            int
	aggSelected                          [viewList]int
	block                                int
	blockSelected                        [blockCount]int
	summary                              *tuiSummary
	summaryKey                           string
	summaryAt                            time.Time
	drill                                *tuiDrill
	searchInput                          *textinput.Model
	searchTerm                           string
	searchLines                          []int
	searchIndex                          int
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
func (m tuiModel) listTab() bool {
	return m.tab == tabRequests || (m.tab == tabAlerts && m.alertView == viewList)
}
func (m tuiModel) aggView() bool { return m.tab == tabAlerts && m.alertView != viewList && !m.details }

// summaryScope says whether the page shows aggregates and which filter they use.
// The overview always covers the whole session.
func (m tuiModel) summaryScope() (bool, tuiFilter, string) {
	switch {
	case m.tab == tabOverview && !m.details:
		return true, tuiFilter{}, "overview"
	case m.aggView():
		return true, m.filter, fmt.Sprintf("alerts %#v", m.filter)
	}
	return false, tuiFilter{}, ""
}

// currentSummary returns the summary only when it matches the visible page.
func (m tuiModel) currentSummary() *tuiSummary {
	if ok, _, key := m.summaryScope(); ok && key == m.summaryKey {
		return m.summary
	}
	return nil
}
func (m tuiModel) modal() bool { return m.form != nil || m.export != nil }

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
	wantSummary, summaryFilter, summaryKey := m.summaryScope()
	wantSummary = wantSummary && (summaryKey != m.summaryKey || m.summary == nil || time.Since(m.summaryAt) >= tuiSummaryInterval)
	rootCtx, store := m.ctx, m.store
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(rootCtx, 3*time.Second)
		defer cancel()
		snapshot, err := loadTUISnapshot(ctx, store, filter, alertsOnly, page, detailID, anchor)
		result := tuiLoaded{Version: version, Snapshot: snapshot, Err: err}
		if err == nil && wantSummary {
			result.Summary, result.Err = loadTUISummary(ctx, store, summaryFilter)
			result.SummaryKey = summaryKey
		}
		return result
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
	}
	wrapped := termansi.Hardwrap(content, max(1, m.viewport.Width()), true)
	m.viewport.SetContent(wrapped)
	m.findSearchLines(wrapped)
}

// switchTab keeps each list tab's own page and cursor.
func (m *tuiModel) switchTab(tab int) tea.Cmd {
	if tab == m.tab && !m.details {
		return nil
	}
	m.lists[m.tab] = tuiListState{m.page, m.selected}
	m.drill = nil
	m.tab = tab
	m.page, m.selected = m.lists[tab].page, m.lists[tab].selected
	m.closeDetail()
	m.stale = true
	m.viewport.GotoTop()
	m.resize()
	return m.changed()
}
func (m *tuiModel) closeDetail() {
	m.searchTerm, m.searchInput, m.searchLines = "", nil, nil
	m.details = false
	m.detailID = ""
	m.pickDetail = false
	m.snapshot.Detail = nil
	m.snapshot.DetailMissing = false
}
func (m *tuiModel) applyFilter(filter tuiFilter) tea.Cmd {
	m.drill = nil
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
				if msg.Summary != nil {
					m.summary, m.summaryKey, m.summaryAt = msg.Summary, msg.SummaryKey, time.Now()
				}
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
	if m.details && !m.pickDetail {
		for i, row := range m.snapshot.Rows {
			if row.ID == m.detailID {
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
	if m.searchInput != nil {
		return m, m.updateSearch(msg)
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
		if m.details {
			return m, m.openSearch()
		}
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
		if m.details && m.searchTerm != "" {
			m.searchTerm = ""
			m.updateContent()
			return m, nil
		}
		if m.details {
			m.closeDetail()
			m.viewport.GotoTop()
			m.resize()
			return m, m.changed()
		}
		if m.drill != nil {
			return m, m.returnFromDrill()
		}
		return m, nil
	case "v":
		if m.tab == tabAlerts && !m.details {
			m.drill = nil
			m.alertView = (m.alertView + 1) % alertViewCount
			m.page, m.selected = 0, 0
			m.stale = true
			return m, m.changed()
		}
	}
	if m.aggView() {
		return m, m.updateAggKey(key)
	}
	if m.tab == tabOverview && !m.details {
		return m, m.updateOverviewKey(key)
	}
	if m.details || m.listTab() {
		switch key {
		case "c", "m", "H":
			return m, m.toggleFromRow(key)
		case "e":
			return m, m.openExport()
		case "y":
			return m, m.copyID()
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
		case "n", "N":
			if m.searchTerm != "" {
				step := 1
				if key == "N" {
					step = -1
				}
				m.jumpSearch(step)
				return m, nil
			}
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
