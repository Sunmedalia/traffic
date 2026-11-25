package main

// Mouse support. Clickable text is wrapped in invisible zone markers while a
// frame is rendered; View strips them before the frame reaches the terminal,
// and a click renders the frame again to find the zone under the pointer.
// Most zones name a key ("key:L"), so a click does exactly what the key does.

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

// Zone markers are APC sequences: every ANSI-aware helper treats them as zero
// width and keeps them through styling, truncation and padding.
const (
	tuiHitOpen  = "\x1b_tz;"
	tuiHitClose = "\x1b_tz\x1b\\"
	tuiHitST    = "\x1b\\"
)

// tuiHit marks text as a clickable zone. A zone ends at its line, so text
// spanning lines needs a zone per line.
func tuiHit(id, text string) string {
	return tuiHitOpen + id + tuiHitST + text + tuiHitClose
}

type tuiHitZone struct {
	id        string
	y, x0, x1 int
}

// tuiHitScan removes the zone markers from a frame and returns where each zone landed.
func tuiHitScan(frame string) (string, []tuiHitZone) {
	if !strings.Contains(frame, "\x1b_tz") {
		return frame, nil
	}
	lines := strings.Split(frame, "\n")
	zones := []tuiHitZone{}
	type open struct {
		id string
		x  int
	}
	for y, line := range lines {
		var clean strings.Builder
		stack := []open{}
		x := 0
		for {
			i := strings.Index(line, "\x1b_tz")
			if i < 0 {
				break
			}
			clean.WriteString(line[:i])
			x += termansi.StringWidth(line[:i])
			line = line[i:]
			if strings.HasPrefix(line, tuiHitClose) {
				line = line[len(tuiHitClose):]
				if n := len(stack); n > 0 {
					zones = append(zones, tuiHitZone{stack[n-1].id, y, stack[n-1].x, x})
					stack = stack[:n-1]
				}
				continue
			}
			end := strings.Index(line, tuiHitST)
			if !strings.HasPrefix(line, tuiHitOpen) || end < 0 {
				// Not one of ours: keep it as text.
				clean.WriteString(line[:4])
				line = line[4:]
				continue
			}
			stack = append(stack, open{line[len(tuiHitOpen):end], x})
			line = line[end+len(tuiHitST):]
		}
		clean.WriteString(line)
		x += termansi.StringWidth(line)
		for i := len(stack) - 1; i >= 0; i-- {
			zones = append(zones, tuiHitZone{stack[i].id, y, stack[i].x, x})
		}
		lines[y] = clean.String()
	}
	return strings.Join(lines, "\n"), zones
}

// tuiHitFind returns the innermost zone under a cell.
func tuiHitFind(zones []tuiHitZone, x, y int) string {
	best, width := "", 0
	for _, z := range zones {
		if z.y == y && x >= z.x0 && x < z.x1 && (best == "" || z.x1-z.x0 < width) {
			best, width = z.id, z.x1-z.x0
		}
	}
	return best
}

// tuiKeyMsg builds the key press a key name stands for, as msg.String() spells it.
func tuiKeyMsg(name string) tea.KeyPressMsg {
	codes := map[string]rune{
		"enter": tea.KeyEnter, "esc": tea.KeyEscape, "tab": tea.KeyTab, "backspace": tea.KeyBackspace,
		"up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight,
		"home": tea.KeyHome, "end": tea.KeyEnd, "pgup": tea.KeyPgUp, "pgdown": tea.KeyPgDown,
	}
	mod, base := tea.KeyMod(0), name
	switch {
	case strings.HasPrefix(name, "shift+"):
		mod, base = tea.ModShift, strings.TrimPrefix(name, "shift+")
	case strings.HasPrefix(name, "ctrl+"):
		mod, base = tea.ModCtrl, strings.TrimPrefix(name, "ctrl+")
	}
	if code, ok := codes[base]; ok {
		return tea.KeyPressMsg{Code: code, Mod: mod}
	}
	if base == "space" {
		return tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	}
	r := []rune(base)
	if mod != 0 {
		return tea.KeyPressMsg{Code: r[0], Mod: mod}
	}
	return tea.KeyPressMsg{Code: r[0], Text: base}
}

var tuiHintNames = map[string]string{
	"Esc": "esc", "Enter": "enter", "Tab": "tab", "Backspace": "backspace", "空格": "space",
	"Ctrl+R": "ctrl+r", "PgUp": "pgup", "PgDn": "pgdown", "↑": "up", "↓": "down", "←": "left", "→": "right",
}

// tuiHintKey names the key a hint label shows, or "" when it is not one key.
func tuiHintKey(label string) string {
	if key, ok := tuiHintNames[label]; ok {
		return key
	}
	if r := []rune(label); len(r) == 1 && r[0] > ' ' && r[0] < 0x7f {
		return label
	}
	return ""
}

// tuiHints makes each "key action" item of a " · " separated hint line
// clickable. Items naming several keys ("j/k", "[ ]", "←→") get a zone per key.
func tuiHints(line string) string {
	items := strings.Split(line, " · ")
	for i, item := range items {
		items[i] = tuiHintItem(item)
	}
	return strings.Join(items, " · ")
}

func tuiHintItem(item string) string {
	trimmed := strings.TrimLeft(item, " ")
	lead := item[:len(item)-len(trimmed)]
	for _, pair := range []string{"[ ]", "< >"} {
		if strings.HasPrefix(trimmed, pair+" ") {
			return lead + tuiHit("key:"+pair[:1], pair[:1]) + " " + tuiHit("key:"+pair[2:3], pair[2:3]) + trimmed[3:]
		}
	}
	label, _, ok := strings.Cut(trimmed, " ")
	if !ok {
		return item
	}
	if key := tuiHintKey(label); key != "" {
		return lead + tuiHit("key:"+key, trimmed)
	}
	parts, sep := strings.Split(label, "/"), "/"
	if label == "↑↓" || label == "←→" {
		parts, sep = []string{label[:3], label[3:]}, ""
	}
	if len(parts) < 2 {
		return item
	}
	marked := make([]string, len(parts))
	for i, part := range parts {
		key := tuiHintKey(part)
		if key == "" {
			return item
		}
		marked[i] = tuiHit("key:"+key, part)
	}
	return lead + strings.Join(marked, sep) + trimmed[len(label):]
}

// tuiButton draws a clickable dialog button for a key.
func tuiButton(key, label string) string {
	return tuiHit("key:"+key, tuiAccent.Render("[ "+label+" ]"))
}

// tuiTimelineDrag follows a press on the timeline until the button is released.
type tuiTimelineDrag struct {
	start  int
	again  bool // the press landed on the column that was already the selection
	inside bool // the press landed inside a selected span, which it keeps unless dragged
	moved  bool
	armed  bool // on the overview, the selection was made by an earlier click
}

// tuiScrollDrag follows a press on the list scrollbar; grab is where the
// thumb was taken, counted from its top cell.
type tuiScrollDrag struct{ grab int }

// tuiDoubleClick is the longest gap between the clicks of a double click.
const tuiDoubleClick = 400 * time.Millisecond

func (m tuiModel) zones() []tuiHitZone {
	_, zones := tuiHitScan(m.render())
	return zones
}
func (m tuiModel) hitAt(x, y int) string { return tuiHitFind(m.zones(), x, y) }

// timelineColumnAt maps an x position to a timeline column, clamping to the ends.
func (m tuiModel) timelineColumnAt(x int) int {
	first, last := -1, -1
	firstX, lastX := 0, 0
	for _, z := range m.zones() {
		id, ok := strings.CutPrefix(z.id, "tl:")
		if !ok {
			continue
		}
		i, _ := strconv.Atoi(id)
		if x >= z.x0 && x < z.x1 {
			return i
		}
		if first < 0 || z.x0 < firstX {
			first, firstX = i, z.x0
		}
		if last < 0 || z.x1 > lastX {
			last, lastX = i, z.x1
		}
	}
	if first >= 0 && x < firstX {
		return first
	}
	return last
}

func (m *tuiModel) updateMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	mouse := msg.Mouse()
	switch msg.(type) {
	case tea.MouseClickMsg:
		switch mouse.Button {
		case tea.MouseLeft:
			id := m.hitAt(mouse.X, mouse.Y)
			now := time.Now()
			double := id != "" && id == m.lastClick && now.Sub(m.lastClickAt) < tuiDoubleClick
			m.lastClick, m.lastClickAt = id, now
			if double {
				m.lastClick = "" // a third click starts over
			}
			m.flash = ""
			m.pressX = mouse.X
			return m, m.click(id, mouse.Y, double)
		case tea.MouseRight, tea.MouseBackward:
			// Right click goes back a level, like Esc.
			return m.updateKey(tuiKeyMsg("esc"))
		}
	case tea.MouseMotionMsg:
		var cmd tea.Cmd
		if m.splitDrag {
			cmd = m.dragDivider(mouse.X)
		}
		if m.scrollDrag != nil {
			m.dragScrollbar(mouse.Y)
		}
		if m.colDrag != nil {
			m.dragColumn(mouse.X)
		}
		if d := m.drag; d != nil {
			col := m.timelineColumnAt(mouse.X)
			if col < 0 || d.inside && !d.moved && col == d.start {
				return m, cmd
			}
			if d.inside && !d.moved {
				// Dragging from inside a span starts a new one.
				m.timelineAnchor = d.start + 1
			}
			d.moved = true
			m.blockSelected[blockTimeline] = col
		}
		return m, cmd
	case tea.MouseReleaseMsg:
		m.scrollDrag = nil
		m.endColumnDrag()
		if m.splitDrag {
			m.splitDrag = false
			if m.wrapStale {
				// The drag is over, so wrap for the final width without waiting.
				m.updateContent()
			}
			m.flash = fmt.Sprintf("列表 %d 列 · 详情 %d 列 · 双击分隔线恢复各占一半", m.listWidth(), m.viewport.Width())
		}
		if m.drag != nil {
			return m, m.endDrag()
		}
	case tea.MouseWheelMsg:
		step := 0
		switch mouse.Button {
		case tea.MouseWheelUp:
			step = -1
		case tea.MouseWheelDown:
			step = 1
		}
		if step != 0 {
			return m, m.wheel(mouse.X, mouse.Y, step)
		}
	}
	return m, nil
}

// click runs the action of a zone.
func (m *tuiModel) click(id string, y int, double bool) tea.Cmd {
	kind, arg, _ := strings.Cut(id, ":")
	if m.help && (kind != "key" || y != m.height-1) {
		// The help's own keys scroll or close it; a click elsewhere closes it.
		m.help = false
		return nil
	}
	n, _ := strconv.Atoi(arg)
	armed := m.armed
	m.armed = ""
	switch kind {
	case "key":
		_, cmd := m.updateKey(tuiKeyMsg(arg))
		return cmd
	case "ffield", "fopt":
		if m.form == nil {
			return nil
		}
		field, option, _ := strings.Cut(arg, ":")
		f := m.form
		f.index, _ = strconv.Atoi(field)
		if kind == "fopt" {
			f.fields[f.index].choice, _ = strconv.Atoi(option)
		}
		return f.focus()
	case "arule":
		if m.analysis != nil && m.analysis.open {
			m.analysis.choice = n
		}
		return nil
	case "dpick":
		if m.decoder != nil && m.decoder.picking {
			m.decoder.picking = false
			m.applyDecoder(tuiDecoders[n])
		}
		return nil
	}
	// The remaining zones live on pages behind any dialog or input.
	if m.modal() {
		return nil
	}
	switch kind {
	case "tab":
		return m.switchTab(n)
	case "filter":
		m.form = newTUIForm(m.filter, m.services(), m.width)
		return m.form.focus()
	case "chip":
		return m.applyFilter(m.filter.without(arg))
	case "row":
		if m.stale || n >= len(m.snapshot.Rows) {
			return nil
		}
		m.selected = n
		if m.details && m.detailID == m.snapshot.Rows[n].ID {
			// A later click on the open record hides the detail again; the
			// second half of a double click keeps it open.
			if double {
				return nil
			}
			return m.hideDetail()
		}
		return m.openDetail(m.snapshot.Rows[n])
	case "page":
		switch arg {
		case "next":
			return m.gotoPage(m.page + 1)
		case "prev":
			return m.gotoPage(m.page - 1)
		}
		m.listFree = false
		return m.gotoPage(0)
	case "divider":
		if double {
			m.listRatio = 0
			m.listShare = 0
			m.resize()
			m.flash = "列表与详情各占一半"
			return nil
		}
		m.splitDrag = true
	case "col":
		m.startColumnDrag(n, m.pressX, double)
		return nil
	case "tl":
		m.startDrag(n, armed == "timeline")
		return nil
	case "sb":
		m.pressScrollbar(n)
		return nil
	case "aview":
		if m.alertView != n {
			m.drill = nil
			m.alertView = n
			m.page, m.selected = 0, 0
			m.stale = true
			return m.changed()
		}
	case "agg":
		m.aggSelected[m.alertView] = n
		return m.updateAggKey("enter")
	case "block":
		m.block, m.timelineAnchor = n, 0
	case "ov":
		// On the overview a first click shows a summary and a second click
		// on the same row opens it, so a stray click does not leave the page.
		block, item, _ := strings.Cut(arg, ":")
		m.block, _ = strconv.Atoi(block)
		m.blockSelected[m.block], _ = strconv.Atoi(item)
		m.timelineAnchor = 0
		if armed == id {
			return m.updateOverviewKey("enter")
		}
		m.armed = id
		m.flash = m.overviewBrief(m.block, m.blockSelected[m.block])
	case "dtab":
		m.setDetailTab(n)
	case "param":
		m.paramSelected = n
		m.updateContent()
		cmd, _ := m.updateParamsKey("enter")
		return cmd
	case "dstep":
		if d := m.decoder; d != nil && n < len(d.steps) {
			d.steps = d.steps[:n+1]
			d.err = ""
			d.hex = tuiLooksBinary(d.last())
			m.updateContent()
		}
	}
	return nil
}

func (m tuiModel) overviewPage() bool { return m.tab == tabOverview && !m.details }

// startDrag begins a timeline selection on the pressed column.
func (m *tuiModel) startDrag(col int, armed bool) {
	focused := m.timelineFocus
	if m.overviewPage() {
		focused = m.block == blockTimeline
		m.block = blockTimeline
	} else {
		m.timelineFocus = true
	}
	d := &tuiTimelineDrag{start: col, armed: armed}
	m.drag = d
	cursor := m.blockSelected[blockTimeline]
	if focused && m.timelineAnchor > 0 {
		if from, to := min(cursor, m.timelineAnchor-1), max(cursor, m.timelineAnchor-1); col >= from && col <= to {
			d.inside = true
			return
		}
	}
	d.again = focused && m.timelineAnchor == 0 && cursor == col
	m.blockSelected[blockTimeline], m.timelineAnchor = col, col+1
}

// endDrag finishes a press on the timeline. On a list a dragged span, or a
// second click on the selection, applies it like a drag on the web timeline.
// The overview only selects; clicking the selection again, or Enter, opens
// the requests.
func (m *tuiModel) endDrag() tea.Cmd {
	d := m.drag
	m.drag = nil
	clicked := !d.moved && (d.inside || m.blockSelected[blockTimeline] == d.start)
	if clicked && !d.inside {
		m.timelineAnchor = 0
	}
	apply := !clicked || d.inside || d.again
	if m.overviewPage() {
		if clicked && d.armed && (d.inside || d.again) {
			return m.updateOverviewKey("enter")
		}
		m.armed = "timeline"
		m.flash = "已选中时间段 · 再点一次选中处或按 Enter 查看这段时间的请求"
		return nil
	}
	if !apply {
		return nil
	}
	cmd, _ := m.updateListTimeline("enter")
	return cmd
}

// dragDivider follows the pointer with the divider between list and detail.
// The divider's line sits one column after the list.
func (m *tuiModel) dragDivider(x int) tea.Cmd {
	if !m.split() || m.width <= 0 {
		return nil
	}
	width := max(tuiMinList, min(m.width-tuiMinDetail-3, x-1))
	if width == m.listWidth() {
		return nil // re-wrapping a large detail on every motion event is costly
	}
	m.listRatio = max(1, (width*1000+m.width-1)/m.width)
	return m.resizeSoon()
}

// scrollListTo moves the list window. Beside a detail the list scrolls on
// its own; a full list keeps the cursor on a visible row.
func (m *tuiModel) scrollListTo(top int) {
	_, visible := m.listLayout(m.listBox())
	m.listTop = max(0, min(len(m.snapshot.Rows)-visible, top))
	if m.split() {
		m.listFree = true
		return
	}
	m.selected = max(m.listTop, min(m.listTop+visible-1, m.selected))
	m.selected = min(m.selected, max(0, len(m.snapshot.Rows)-1))
}

// tuiThumb places the scrollbar thumb for n rows with visible shown from top.
func tuiThumb(n, visible, top int) (int, int) {
	if n <= visible {
		return 0, visible
	}
	thumb := max(1, visible*visible/n)
	return (top*(visible-thumb) + (n-visible)/2) / (n - visible), thumb
}

// tuiThumbTop is the first row shown when the thumb starts at cell.
func tuiThumbTop(n, visible, thumb, cell int) int {
	if visible <= thumb {
		return 0
	}
	return (cell*(n-visible) + (visible-thumb)/2) / (visible - thumb)
}

// pressScrollbar grabs the thumb, or pages the list to the pressed cell like
// a click on a scrollbar track.
func (m *tuiModel) pressScrollbar(cell int) {
	_, visible := m.listLayout(m.listBox())
	n := len(m.snapshot.Rows)
	start, thumb := tuiThumb(n, visible, m.listStart(visible))
	grab := cell - start
	if grab < 0 || grab >= thumb {
		grab = thumb / 2
		m.scrollListTo(tuiThumbTop(n, visible, thumb, cell-grab))
	}
	m.scrollDrag = &tuiScrollDrag{grab: grab}
}

// dragScrollbar follows the pointer while the thumb is held.
func (m *tuiModel) dragScrollbar(y int) {
	top := -1
	for _, z := range m.zones() {
		if z.id == "sb:0" {
			top = z.y
		}
	}
	if top < 0 {
		return
	}
	_, visible := m.listLayout(m.listBox())
	n := len(m.snapshot.Rows)
	_, thumb := tuiThumb(n, visible, m.listStart(visible))
	m.scrollListTo(tuiThumbTop(n, visible, thumb, y-top-m.scrollDrag.grab))
}

// wheel scrolls whatever is under the pointer.
func (m *tuiModel) wheel(x, y, step int) tea.Cmd {
	key := map[int]string{-1: "up", 1: "down"}[step]
	switch {
	case m.help:
		m.moveHelp(3 * step)
		return nil
	case m.analysis != nil && m.analysis.open, m.form != nil, m.details && m.decoder != nil && m.decoder.picking:
		_, cmd := m.updateKey(tuiKeyMsg(key))
		return cmd
	case m.modal():
		return nil
	case m.aggView():
		tuiMove(&m.aggSelected[m.alertView], key, m.aggLen(), 1)
		return nil
	case m.tab == tabOverview && !m.details:
		m.block = max(0, min(blockCount-1, m.block+step))
		m.timelineAnchor = 0
		return nil
	case m.split() && x < m.listWidth():
		// Scroll the list beside a detail without changing the open record.
		m.scrollListTo(m.listTop + 3*step)
		return nil
	case m.details || !m.listTab():
		if step < 0 {
			m.viewport.ScrollUp(3)
		} else {
			m.viewport.ScrollDown(3)
		}
		return nil
	}
	// A list scrolls by three rows and keeps the cursor on a visible row.
	m.scrollListTo(m.listTop + 3*step)
	return nil
}

// listBox is the size the list is drawn at on the current page.
func (m tuiModel) listBox() (int, int) {
	width, height := max(1, m.width), m.contentHeight()
	switch {
	case m.split():
		width = m.listWidth() - 1
	case m.tab == tabAlerts:
		height = max(1, height-1) // the view switcher
	}
	return width, height
}

// listLayout returns the timeline strip above the list and how many rows fit below it.
func (m tuiModel) listLayout(width, height int) ([]string, int) {
	var strip []string
	if timeline := m.listTimeline(); timeline != nil && !m.split() && (height >= 10 && !m.timelineFocus || height >= 16) {
		strip = m.listTimelineView(timeline, width)
		height -= len(strip)
	}
	return strip, max(1, height-2)
}

// keepListCursor scrolls the list just enough to show the cursor, unless the
// wheel moved the list away from it.
func (m *tuiModel) keepListCursor() {
	if m.listFree || !m.listTab() || m.details && !m.split() {
		return
	}
	_, visible := m.listLayout(m.listBox())
	if m.selected < m.listTop {
		m.listTop = m.selected
	}
	if m.selected >= m.listTop+visible {
		m.listTop = m.selected - visible + 1
	}
	m.listTop = max(0, min(m.listTop, len(m.snapshot.Rows)-visible))
}

// listStart is the first row drawn.
func (m tuiModel) listStart(visible int) int {
	return max(0, min(m.listTop, len(m.snapshot.Rows)-visible))
}

// without drops one filter condition, named like the filter chips.
func (f tuiFilter) without(field string) tuiFilter {
	switch field {
	case "keyword":
		f.Keyword = ""
	case "decode":
		f.Decode = 0
	case "severity":
		f.Severity = ""
	case "status":
		f.Status = ""
	case "method":
		f.Method = ""
	case "static":
		f.HideStatic = false
	case "exclude":
		f.Exclude = ""
	case "param":
		f.Param = ""
	case "client":
		f.Client = ""
	case "rule":
		f.Rule = ""
	case "service":
		f.Service = ""
	case "time":
		f.Since, f.Until, f.UntilExclusive = "", "", false
	}
	return f
}

// toggleMouse lets the terminal select text again, since captured mouse
// input stops the terminal's own selection.
func (m *tuiModel) toggleMouse() {
	m.noMouse = !m.noMouse
	if m.noMouse {
		m.flash = "已关闭鼠标操作，可用终端直接选取文字；按 M 重新开启"
	} else {
		m.flash = fmt.Sprintf("已开启鼠标操作：点击、滚轮、拖动时间线%s", tuiMouseSelectNote)
	}
}

const tuiMouseSelectNote = "（多数终端按住 Shift 仍可选取文字）"
