package main

import (
	"context"
	"fmt"
	"time"

	lipgloss "charm.land/lipgloss/v2"

	"charm.land/bubbles/v2/key"
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
	Version     uint64
	Snapshot    tuiSnapshot
	Err         error
	Summary     *tuiSummary
	SummaryKey  string
	Overview    *tuiOverview
	Timeline    *sessionTimeline
	TimelineKey string
}

// Alert tab views. The list comes first, as on the web page.
const (
	viewRules = iota
	viewSources
	viewList
	alertViewCount
)

// Detail tabs follow the web detail pane.
const (
	detailRequest = iota
	detailResponse
	detailDecoder
	detailDecoded
	detailAlerts
	detailParams
	detailTabCount
)

var tuiDetailNames = [detailTabCount]string{"请求", "响应", "解码", "解压正文", "检测依据", "参数"}

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

// tuiBodies caches the decoded bodies of the open record between renders.
type tuiBodies struct {
	key                    string
	request, requestView   string
	response, responseView string
}

type tuiModel struct {
	ctx                                  context.Context
	store                                *Store
	refresh                              time.Duration
	rulesDir                             string
	filter                               tuiFilter
	snapshot                             tuiSnapshot
	title                                string
	width, height, tab, page, selected   int
	detailTab                            int
	lists                                [tuiTabCount]tuiListState
	version                              uint64
	busy, pending, paused, details, help bool
	stale, pickDetail                    bool
	raw, metaOpen                        bool
	noMouse, listFree                    bool
	listTop                              int // first list row drawn
	drag                                 *tuiTimelineDrag
	scrollDrag                           *tuiScrollDrag
	lastClick                            string // zone of the last click, for double clicks
	lastClickAt                          time.Time
	msgLayout, listShare                 int
	paramSelected                        int
	detailID, errorText, flash           string
	alertView                            int
	aggSelected                          [viewList]int
	block                                int
	blockSelected                        [blockCount]int
	timelineAnchor                       int // selection start + 1; 0 when none
	timelineFocus                        bool
	summary                              *tuiSummary
	summaryKey                           string
	summaryAt                            time.Time
	overview                             *tuiOverview
	overviewAt                           time.Time
	timeline                             *sessionTimeline
	timelineKey                          string
	timelineAt                           time.Time
	drill                                *tuiDrill
	searchInput                          *textinput.Model
	searchTerm                           string
	searchLines                          []int
	searchIndex                          int
	form                                 *tuiForm
	export                               *tuiExport
	decoder                              *tuiDecoder
	bodies                               tuiBodies
	analysis                             *tuiAnalysis
	viewport                             viewport.Model
}

var tuiAccent = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#5FD7D7"))
var tuiMuted = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
var tuiSelected = lipgloss.NewStyle().Reverse(true)
var tuiDanger = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF7777"))
var tuiWarn = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6C35C"))
var tuiGood = lipgloss.NewStyle().Foreground(lipgloss.Color("#7BD88F"))
var tuiBold = lipgloss.NewStyle().Bold(true)

// tuiViewportKeys leaves letters free for page actions; j and k only scroll
// pages without records, because the detail uses them to change record.
func tuiViewportKeys() viewport.KeyMap {
	return viewport.KeyMap{
		PageDown:     key.NewBinding(key.WithKeys("pgdown")),
		PageUp:       key.NewBinding(key.WithKeys("pgup")),
		HalfPageUp:   key.NewBinding(key.WithKeys("ctrl+u")),
		HalfPageDown: key.NewBinding(key.WithKeys("ctrl+d")),
		Up:           key.NewBinding(key.WithKeys("up", "k")),
		Down:         key.NewBinding(key.WithKeys("down", "j")),
	}
}

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

// summaryScope says whether the page shows alert aggregates and which filter they use.
func (m tuiModel) summaryScope() (bool, tuiFilter, string) {
	if m.aggView() {
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

// timelineScope names the list timeline shown above the visible list.
func (m tuiModel) timelineScope() string {
	if !m.listTab() || m.details {
		return ""
	}
	return fmt.Sprintf("%d %#v", m.tab, m.filter)
}
func (m tuiModel) listTimeline() *sessionTimeline {
	if key := m.timelineScope(); key != "" && key == m.timelineKey {
		return m.timeline
	}
	return nil
}

// modal reports a dialog or input that owns the keyboard.
func (m tuiModel) modal() bool {
	return m.form != nil || m.export != nil || m.analysis != nil && m.analysis.open || m.searchInput != nil || m.decoder != nil && m.decoder.capturing()
}

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
	wantOverview := m.tab == tabOverview && !m.details && (m.overview == nil || time.Since(m.overviewAt) >= tuiSummaryInterval)
	timelineKey := m.timelineScope()
	wantTimeline := timelineKey != "" && (timelineKey != m.timelineKey || m.timeline == nil || time.Since(m.timelineAt) >= tuiSummaryInterval)
	timelineFilter := m.filter
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
		if result.Err == nil && wantOverview {
			result.Overview, result.Err = loadTUIOverview(ctx, store)
		}
		if result.Err == nil && wantTimeline {
			result.Timeline, result.Err = loadTUITimeline(ctx, store, timelineFilter, alertsOnly)
			result.TimelineKey = timelineKey
		}
		return result
	}
}
func (m *tuiModel) changed() tea.Cmd  { m.version++; return m.load() }
func (m tuiModel) contentHeight() int { return max(1, m.height-tuiChrome) }
func (m tuiModel) split() bool        { return m.details && m.width >= 120 && m.listShare < 2 }

// listWidth is the list's share of a split detail: half, then a third.
func (m tuiModel) listWidth() int {
	if m.listShare == 1 {
		return m.width / 3
	}
	return m.width / 2
}
func (m *tuiModel) resize() {
	width := max(1, m.width)
	if m.split() {
		width = max(1, m.width-m.listWidth()-3)
	}
	m.viewport.KeyMap = tuiViewportKeys()
	m.viewport.SetWidth(width)
	m.viewport.SetHeight(m.contentHeight())
	m.updateContent()
}
func (m *tuiModel) updateContent() {
	content := ""
	switch {
	case m.details:
		m.cacheBodies()
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
	m.timelineFocus, m.timelineAnchor = false, 0
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
	m.decoder = nil
	m.snapshot.Detail = nil
	m.snapshot.DetailMissing = false
}
func (m *tuiModel) applyFilter(filter tuiFilter) tea.Cmd {
	m.drill = nil
	m.timelineFocus, m.timelineAnchor = false, 0
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
	m.detailTab = detailRequest
	m.decoder = nil
	m.paramSelected = 0
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

// refreshNow drops cached aggregates so the next load rebuilds them, like r on the web.
func (m *tuiModel) refreshNow() tea.Cmd {
	m.summaryAt, m.overviewAt, m.timelineAt = time.Time{}, time.Time{}, time.Time{}
	return m.load()
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	model, cmd := m.update(msg)
	m.keepListCursor()
	return model, cmd
}

func (m *tuiModel) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.MouseMsg:
		return m.updateMouse(msg)
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		return m, nil
	case tuiTick:
		var load tea.Cmd
		// Finished sessions only refresh on demand, as on the web page.
		if !m.paused && (tuiLive(m.snapshot.Stats.State) || m.overview == nil && m.tab == tabOverview) {
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
				if msg.Overview != nil {
					m.overview, m.overviewAt = msg.Overview, time.Now()
				}
				if msg.Timeline != nil {
					m.timeline, m.timelineKey, m.timelineAt = msg.Timeline, msg.TimelineKey, time.Now()
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
	case tuiAnalysisTick:
		if m.analysisRunning() {
			return m, m.analysisTick()
		}
		return m, nil
	case tuiAnalysisDone:
		return m, m.finishAnalysis(msg)
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
	if m.decoder != nil && m.decoder.editor != nil {
		var cmd tea.Cmd
		*m.decoder.editor, cmd = m.decoder.editor.Update(msg)
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
	if m.analysis != nil && m.analysis.open {
		return m, m.updateAnalysis(key)
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
	if m.details && m.decoder != nil && m.decoder.capturing() {
		return m, m.updateDecoderModal(msg)
	}
	m.flash = ""
	m.listFree = false
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
		if !m.paused && !tuiLive(m.snapshot.Stats.State) {
			m.flash = "会话已结束，不再自动刷新；按 r 立即刷新"
			return m, nil
		}
		m.paused = !m.paused
		if !m.paused {
			return m, m.load()
		}
		return m, nil
	case "r":
		return m, m.refreshNow()
	case "z":
		tuiUseUTC.Store(!tuiUseUTC.Load())
		m.updateContent()
		return m, nil
	case "A":
		return m, m.openAnalysis()
	case "M":
		m.toggleMouse()
		return m, nil
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
		if m.timelineFocus {
			m.timelineFocus, m.timelineAnchor = false, 0
			return m, nil
		}
		if m.tab == tabOverview && m.timelineAnchor > 0 {
			m.timelineAnchor = 0
			return m, nil
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
		case "c", "m", "H", "S":
			return m, m.toggleFromRow(key)
		case "e":
			return m, m.openExport()
		case "y":
			return m, m.copyID()
		}
	}
	if m.details {
		if cmd, ok := m.updateDetailKey(msg); ok {
			return m, cmd
		}
	}
	if m.details || !m.listTab() {
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}
	if cmd, ok := m.updateListTimeline(key); ok {
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

// updateDetailKey handles the detail pane's own keys; ok is false for keys
// left to the viewport.
func (m *tuiModel) updateDetailKey(msg tea.KeyPressMsg) (tea.Cmd, bool) {
	key := msg.String()
	if m.detailTab == detailDecoder && m.decoder != nil {
		if cmd, ok := m.updateDecoderKey(key); ok {
			return cmd, true
		}
	}
	if m.activeDetailTab() == detailParams {
		if cmd, ok := m.updateParamsKey(key); ok {
			return cmd, true
		}
	}
	switch key {
	case "tab", "]", "shift+tab", "[":
		m.stepDetailTab(map[string]int{"tab": 1, "]": 1, "shift+tab": -1, "[": -1}[key])
		return nil, true
	case "n", "N":
		if m.searchTerm != "" {
			step := 1
			if key == "N" {
				step = -1
			}
			m.jumpSearch(step)
			return nil, true
		}
	case "j", "J":
		return m.stepDetail(1), true
	case "k", "K":
		return m.stepDetail(-1), true
	case "d":
		m.openDecoderFor("")
		return nil, true
	case "f":
		m.raw = !m.raw
		if m.raw {
			m.flash = "正文显示原文"
		} else {
			m.flash = "已格式化 JSON 正文"
		}
		m.updateContent()
		return nil, true
	case "i":
		m.metaOpen = !m.metaOpen
		m.updateContent()
		return nil, true
	case "Y":
		return m.copyContent(), true
	case "L":
		m.msgLayout = (m.msgLayout + 1) % layoutCount
		if m.activeDetailTab() != m.detailTab && m.detailTab == detailResponse {
			m.detailTab = detailRequest
		}
		m.flash = "请求与响应：" + tuiLayoutNames[m.msgLayout]
		if m.pairLayout() != m.msgLayout {
			m.flash += fmt.Sprintf("（详情宽度不足 %d 列，暂按上下显示，按 > 加宽详情）", tuiSideMinWidth)
		}
		m.updateContent()
		return nil, true
	case "<", ">":
		if m.width < 120 {
			m.flash = "终端不足 120 列，详情已占满全屏"
			return nil, true
		}
		if key == ">" {
			m.listShare = min(2, m.listShare+1)
		} else {
			m.listShare = max(0, m.listShare-1)
		}
		m.flash = []string{"列表与详情各占一半", "详情占三分之二", "详情全屏，按 < 显示列表"}[m.listShare]
		m.resize()
		return nil, true
	}
	return nil, false
}

// detailTabs lists the tabs this record offers, like the web detail pane.
func (m tuiModel) detailTabs() []int {
	tabs := []int{detailRequest, detailResponse}
	if m.msgLayout != layoutSingle {
		// The request tab shows both messages, as the web pair view does.
		tabs = []int{detailRequest}
	}
	t := m.snapshot.Detail
	if t == nil || t.ID != m.detailID {
		return append(tabs, detailDecoder)
	}
	if len(m.paramGroups()) > 0 {
		tabs = append(tabs, detailParams)
	}
	tabs = append(tabs, detailDecoder)
	if m.bodies.requestView != "" || m.bodies.responseView != "" {
		tabs = append(tabs, detailDecoded)
	}
	if len(t.Alerts) > 0 {
		tabs = append(tabs, detailAlerts)
	}
	return tabs
}
func (m tuiModel) activeDetailTab() int {
	for _, tab := range m.detailTabs() {
		if tab == m.detailTab {
			return tab
		}
	}
	return detailRequest
}
func (m *tuiModel) stepDetailTab(step int) {
	tabs := m.detailTabs()
	at := 0
	for i, tab := range tabs {
		if tab == m.activeDetailTab() {
			at = i
		}
	}
	m.setDetailTab(tabs[(at+step+len(tabs))%len(tabs)])
}
func (m *tuiModel) setDetailTab(tab int) {
	m.detailTab = tab
	if tab == detailDecoder {
		m.currentDecoder()
	}
	m.viewport.GotoTop()
	m.updateContent()
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

// toggleFromRow filters by the client, rule, Host or service of the current record.
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
	case "S":
		service := ""
		if m.details && m.snapshot.Detail != nil && m.snapshot.Detail.ID == row.ID {
			service = m.snapshot.Detail.Service
		}
		if !m.details {
			m.flash = "按 Enter 打开详情后可按服务筛选"
			return nil
		}
		applied = toggle(&filter.Service, service, "该请求没有服务信息")
	}
	if !applied {
		return nil
	}
	if !m.listTab() {
		m.tab = tabRequests
	}
	return m.applyFilter(filter)
}

// updateListTimeline lets t select a time range on the list timeline, like
// dragging across the web list's timeline.
func (m *tuiModel) updateListTimeline(key string) (tea.Cmd, bool) {
	timeline := m.listTimeline()
	if key == "t" {
		if timeline == nil || m.split() {
			m.flash = "时间线还没有数据"
			return nil, true
		}
		m.timelineFocus = !m.timelineFocus
		m.timelineAnchor = 0
		m.blockSelected[blockTimeline] = len(m.timelineColumns(timeline, m.timelinePlot())) - 1
		return nil, true
	}
	if !m.timelineFocus || timeline == nil {
		return nil, false
	}
	switch key {
	case "enter":
		filter := m.filter
		filter.Since, filter.Until = m.timelineSelection(timeline)
		filter.UntilExclusive = true
		return m.applyFilter(filter), true
	case "left", "right", "h", "l", "shift+left", "shift+right", "H", "L", "home", "end", "g", "G", "pgup", "pgdown":
		m.moveTimeline(key, len(m.timelineColumns(timeline, m.timelinePlot())))
		return nil, true
	}
	return nil, false
}
