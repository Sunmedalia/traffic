package main

// The parameter tab lists the query, form and cookie parameters of a request
// as captured. Enter opens the selected value in the decoder.

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

type tuiParamGroup struct {
	title, prefix string
	pairs         [][2]string
}

// paramGroups reads the parameters from the URL and the captured request.
// The prefixes match the decoder's source labels.
func (m tuiModel) paramGroups() []tuiParamGroup {
	t := m.snapshot.Detail
	if t == nil {
		return nil
	}
	groups := []tuiParamGroup{}
	url, _, _ := strings.Cut(t.URL, "#")
	if _, query, ok := strings.Cut(url, "?"); ok {
		if pairs := tuiPairs(query, tuiAmp); len(pairs) > 0 {
			groups = append(groups, tuiParamGroup{"查询参数（原文）", "查询参数", pairs})
		}
	}
	if len(t.Request) > 0 {
		message := tuiSplitHTTP(m.requestText())
		if strings.Contains(strings.ToLower(message.header("content-type")), "x-www-form-urlencoded") {
			if pairs := tuiPairs(message.body, tuiAmp); len(pairs) > 0 {
				groups = append(groups, tuiParamGroup{"表单参数（原文）", "表单参数", pairs})
			}
		}
		if pairs := tuiPairs(message.header("cookie"), tuiSemi); len(pairs) > 0 {
			groups = append(groups, tuiParamGroup{"Cookie（原文）", "Cookie", pairs})
		}
	}
	return groups
}

// paramAt returns the group prefix and pair of the n-th parameter overall.
func (m tuiModel) paramAt(n int) (string, [2]string, int) {
	total := 0
	prefix, pair := "", [2]string{}
	for _, g := range m.paramGroups() {
		for _, p := range g.pairs {
			if total == n {
				prefix, pair = g.prefix, p
			}
			total++
		}
	}
	return prefix, pair, total
}

const tuiParamMarker = "▸ "

func (m tuiModel) paramsContent(width int) []string {
	groups := m.paramGroups()
	nameWidth := 8
	for _, g := range groups {
		for _, p := range g.pairs {
			nameWidth = max(nameWidth, min(24, termansi.StringWidth(tuiLine(p[0]))+2))
		}
	}
	nameWidth = min(nameWidth, max(4, width/3))
	lines := []string{tuiMuted.Render(tuiHints("↑↓ 选择参数 · 点击或 Enter 在解码工具中打开 · Y 复制全部参数"))}
	index := 0
	for _, g := range groups {
		lines = append(lines, "", tuiBold.Render(g.title)+tuiMuted.Render("  "+tuiCount(uint64(len(g.pairs)))+" 个"))
		for _, p := range g.pairs {
			selected := index == m.paramSelected
			id := fmt.Sprintf("param:%d", index)
			index++
			value := tuiLine(p[1])
			if value == "" {
				value = tuiMuted.Render("（空）")
			}
			for i, line := range wrapPlain(value, max(1, width-nameWidth-2)) {
				name := strings.Repeat(" ", nameWidth)
				if i == 0 {
					name = tuiCell(tuiLine(p[0]), nameWidth)
				}
				switch {
				case selected:
					marker := "  "
					if i == 0 {
						marker = tuiParamMarker
					}
					lines = append(lines, tuiHit(id, tuiSelected.Render(tuiCell(marker+name+termansi.Strip(line), width))))
				default:
					if i == 0 {
						name = tuiAccent.UnsetBold().Render(name)
					}
					lines = append(lines, tuiHit(id, "  "+name+m.highlightBody(line)))
				}
			}
		}
	}
	return lines
}

// updateParamsKey moves the parameter cursor and opens the decoder; other
// keys fall through to the detail pane.
func (m *tuiModel) updateParamsKey(key string) (tea.Cmd, bool) {
	_, _, total := m.paramAt(-1)
	switch key {
	case "up", "down":
		if key == "up" {
			m.paramSelected = max(0, m.paramSelected-1)
		} else {
			m.paramSelected = min(total-1, m.paramSelected+1)
		}
		m.updateContent()
		m.revealParam()
		return nil, true
	case "enter":
		prefix, pair, _ := m.paramAt(m.paramSelected)
		if prefix == "" {
			return nil, true
		}
		if pair[1] == "" {
			m.flash = "该参数没有值"
			return nil, true
		}
		m.openDecoderFor(prefix + " " + pair[0])
		return nil, true
	}
	return nil, false
}

// revealParam scrolls the selected parameter into view.
func (m *tuiModel) revealParam() {
	for i, line := range strings.Split(m.viewport.GetContent(), "\n") {
		if strings.HasPrefix(termansi.Strip(line), tuiParamMarker) {
			if i < m.viewport.YOffset() {
				m.viewport.SetYOffset(i)
			} else if bottom := m.viewport.YOffset() + m.viewport.Height(); i >= bottom {
				m.viewport.SetYOffset(i - m.viewport.Height() + 1)
			}
			return
		}
	}
}
