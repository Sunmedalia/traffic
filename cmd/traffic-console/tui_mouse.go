package main

// Mouse support. Clickable text is wrapped in invisible zone markers while a
// frame is rendered; View strips them before the frame reaches the terminal,
// and a click renders the frame again to find the zone under the pointer.
// Most zones name a key ("key:L"), so a click does exactly what the key does.

import (
	"fmt"
	"strconv"
	"strings"

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
	start int
	again bool // the press landed on the column that was already the selection
}

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
			m.flash = ""
			return m, m.click(id)
		case tea.MouseRight, tea.MouseBackward:
			// Right click goes back a level, like Esc.
			return m.updateKey(tuiKeyMsg("esc"))
		}
	case tea.MouseMotionMsg:
		if m.drag != nil {
			if col := m.timelineColumnAt(mouse.X); col >= 0 {
				m.blockSelected[blockTimeline] = col
			}
		}
	case tea.MouseReleaseMsg:
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
func (m *tuiModel) click(id string) tea.Cmd {
	if m.help {
		m.help = false
		return nil
	}
	kind, arg, _ := strings.Cut(id, ":")
	n, _ := strconv.Atoi(arg)
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
			return nil
		}
		return m.openDetail(m.snapshot.Rows[n])
	case "tl":
		m.startDrag(n)
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
		block, item, _ := strings.Cut(arg, ":")
		m.block, _ = strconv.Atoi(block)
		m.blockSelected[m.block], _ = strconv.Atoi(item)
		return m.updateOverviewKey("enter")
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

// startDrag begins a timeline selection on the pressed column.
func (m *tuiModel) startDrag(col int) {
	focused := m.timelineFocus
	if m.tab == tabOverview && !m.details {
		focused = m.block == blockTimeline
		m.block = blockTimeline
	} else {
		m.timelineFocus = true
	}
	cursor := m.blockSelected[blockTimeline]
	again := focused && m.timelineAnchor == 0 && cursor == col
	m.blockSelected[blockTimeline], m.timelineAnchor = col, col+1
	m.drag = &tuiTimelineDrag{start: col, again: again}
}

// endDrag keeps a click as a one-column selection and applies a dragged
// span, or a second click on the same column, like a drag on the web timeline.
func (m *tuiModel) endDrag() tea.Cmd {
	d := m.drag
	m.drag = nil
	if m.blockSelected[blockTimeline] == d.start {
		m.timelineAnchor = 0
		if !d.again {
			return nil
		}
	}
	if m.tab == tabOverview && !m.details {
		return m.updateOverviewKey("enter")
	}
	cmd, _ := m.updateListTimeline("enter")
	return cmd
}

// wheel scrolls whatever is under the pointer.
func (m *tuiModel) wheel(x, y, step int) tea.Cmd {
	key := map[int]string{-1: "up", 1: "down"}[step]
	switch {
	case m.help:
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
		_, visible := m.listLayout(m.listBox())
		m.listTop = max(0, min(len(m.snapshot.Rows)-visible, m.listTop+3*step))
		m.listFree = true
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
	_, visible := m.listLayout(m.listBox())
	m.listTop = max(0, min(len(m.snapshot.Rows)-visible, m.listTop+3*step))
	m.selected = max(m.listTop, min(m.listTop+visible-1, m.selected))
	m.selected = min(m.selected, max(0, len(m.snapshot.Rows)-1))
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
