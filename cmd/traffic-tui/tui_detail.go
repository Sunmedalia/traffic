package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

// Highlights keep reverse video so they stay visible without color.
var tuiMatchStyle = lipgloss.NewStyle().Reverse(true).Bold(true).Foreground(lipgloss.Color("#FF7777"))
var tuiSearchStyle = lipgloss.NewStyle().Reverse(true).Bold(true).Foreground(lipgloss.Color("#E6C35C"))

const tuiHighlightLimit = 10000

// tuiPattern matches any needle literally and case-insensitively, longest first.
func tuiPattern(needles []string) *regexp.Regexp {
	seen := map[string]bool{}
	quoted := []string{}
	for _, needle := range needles {
		needle = strings.TrimSpace(needle)
		if needle == "" || len(needle) > 1024 || seen[strings.ToLower(needle)] {
			continue
		}
		seen[strings.ToLower(needle)] = true
		quoted = append(quoted, regexp.QuoteMeta(needle))
	}
	if len(quoted) == 0 {
		return nil
	}
	sort.Slice(quoted, func(i, j int) bool { return len(quoted[i]) > len(quoted[j]) })
	return regexp.MustCompile("(?i)" + strings.Join(quoted, "|"))
}

// tuiHighlight marks alert matches and search hits in plain text. Search wins
// where both overlap. Styles are applied per line so wrapping stays intact.
func tuiHighlight(text string, alert, search *regexp.Regexp) string {
	if alert == nil && search == nil {
		return text
	}
	marks := make([]byte, len(text))
	mark := func(re *regexp.Regexp, kind byte) {
		if re == nil {
			return
		}
		for _, loc := range re.FindAllStringIndex(text, tuiHighlightLimit) {
			for i := loc[0]; i < loc[1]; i++ {
				marks[i] = kind
			}
		}
	}
	mark(alert, 1)
	mark(search, 2)
	var b strings.Builder
	for start := 0; start < len(text); {
		end := start
		for end < len(text) && marks[end] == marks[start] {
			end++
		}
		segment := text[start:end]
		switch marks[start] {
		case 1:
			segment = tuiStyleLines(segment, tuiMatchStyle)
		case 2:
			segment = tuiStyleLines(segment, tuiSearchStyle)
		}
		b.WriteString(segment)
		start = end
	}
	return b.String()
}
func tuiStyleLines(s string, style lipgloss.Style) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = style.Render(line)
		}
	}
	return strings.Join(lines, "\n")
}

func (m tuiModel) alertPattern() *regexp.Regexp {
	t := m.snapshot.Detail
	if t == nil {
		return nil
	}
	needles := []string{}
	for _, a := range t.Alerts {
		needles = append(needles, a.Match)
	}
	return tuiPattern(needles)
}
func (m tuiModel) searchPattern() *regexp.Regexp {
	if m.searchTerm == "" {
		return nil
	}
	return tuiPattern([]string{m.searchTerm})
}

// highlightBody applies both highlights to a cleaned record body.
func (m tuiModel) highlightBody(text string) string {
	return tuiHighlight(text, m.alertPattern(), m.searchPattern())
}

// tuiOccurrences explains where a match can be seen in the stored text.
func tuiOccurrences(match string, request, response string) string {
	re := tuiPattern([]string{match})
	if re == nil {
		return ""
	}
	inRequest := len(re.FindAllStringIndex(request, tuiHighlightLimit))
	inResponse := len(re.FindAllStringIndex(response, tuiHighlightLimit))
	if inRequest+inResponse == 0 {
		return "请求和响应原文中未直接出现，匹配发生在解码后的视图上"
	}
	return fmt.Sprintf("请求中 %d 处 · 响应中 %d 处，已在对应标签高亮", inRequest, inResponse)
}

// findSearchLines records the wrapped lines that contain the search term.
func (m *tuiModel) findSearchLines(wrapped string) {
	m.searchLines = m.searchLines[:0]
	re := m.searchPattern()
	if re == nil || !m.details {
		return
	}
	for i, line := range strings.Split(wrapped, "\n") {
		if re.MatchString(termansi.Strip(line)) {
			m.searchLines = append(m.searchLines, i)
		}
	}
	m.searchIndex = min(m.searchIndex, max(0, len(m.searchLines)-1))
}

// jumpSearch scrolls to a hit: step 0 picks the first hit at or below the view.
func (m *tuiModel) jumpSearch(step int) {
	if len(m.searchLines) == 0 {
		return
	}
	switch step {
	case 0:
		m.searchIndex = 0
		for i, line := range m.searchLines {
			if line >= m.viewport.YOffset() {
				m.searchIndex = i
				break
			}
		}
	default:
		m.searchIndex = (m.searchIndex + step + len(m.searchLines)) % len(m.searchLines)
	}
	m.viewport.SetYOffset(max(0, m.searchLines[m.searchIndex]-2))
}

func (m *tuiModel) openSearch() tea.Cmd {
	input := textinput.New()
	input.SetVirtualCursor(true)
	input.CharLimit = 256
	input.Prompt = "查找 > "
	input.Placeholder = "要在当前标签中查找的文字"
	input.SetWidth(max(10, m.width-12))
	input.SetValue(m.searchTerm)
	m.searchInput = &input
	return m.searchInput.Focus()
}
func (m *tuiModel) updateSearch(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		m.searchInput = nil
		return nil
	case "enter":
		m.searchTerm = strings.TrimSpace(m.searchInput.Value())
		m.searchInput = nil
		m.searchIndex = 0
		m.updateContent()
		m.jumpSearch(0)
		return nil
	}
	var cmd tea.Cmd
	*m.searchInput, cmd = m.searchInput.Update(msg)
	return cmd
}
func (m tuiModel) searchNotice() string {
	if m.searchTerm == "" || !m.details {
		return ""
	}
	if len(m.searchLines) == 0 {
		return tuiWarn.Render(fmt.Sprintf("查找「%s」未找到 · / 修改 · Esc 清除", tuiLine(m.searchTerm)))
	}
	return tuiAccent.Render(fmt.Sprintf("查找「%s」第 %d/%d 处 · n 下一处 · N 上一处 · Esc 清除", tuiLine(m.searchTerm), m.searchIndex+1, len(m.searchLines)))
}

// copyID sends the request ID to the terminal clipboard over OSC 52.
func (m *tuiModel) copyID() tea.Cmd {
	row, ok := m.currentRow()
	if !ok {
		m.flash = "没有选中的请求"
		return nil
	}
	m.flash = "已发送到剪贴板：" + tuiLine(row.ID) + "（终端不支持 OSC 52 时请手动选取）"
	return tea.SetClipboard(row.ID)
}
