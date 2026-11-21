package main

import (
	"strings"
	"testing"

	lipgloss "charm.land/lipgloss/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

func TestTUIWrapMatchesHardwrap(t *testing.T) {
	styled := tuiAccent.Render("Content-Type") + ": application/json; charset=utf-8"
	inputs := []string{
		"",
		"short",
		strings.Repeat("a", 40),
		strings.Repeat("a", 41),
		"first line\n" + strings.Repeat("x", 95) + "\n\nlast",
		strings.Repeat("中文正文", 12),
		"mixed 中文 and ascii " + strings.Repeat("字", 30),
		styled + " " + styled,
		"  leading spaces " + strings.Repeat("b", 60),
		tuiHit("key:x", "x 清空") + " " + strings.Repeat("·", 50),
	}
	for _, width := range []int{1, 7, 40, 80} {
		for _, input := range inputs {
			want := strings.Split(termansi.Hardwrap(input, width, true), "\n")
			got := tuiWrap(input, width)
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("width %d input %q:\n got %q\nwant %q", width, input, got, want)
			}
		}
	}
	if got := tuiWrap("abc", 0); len(got) != 3 {
		t.Fatalf("width below one must wrap per cell: %q", got)
	}
}

func TestTUIWidthAndPad(t *testing.T) {
	for _, s := range []string{"", "plain ascii", "中文", tuiDanger.Render("red"), "tab\tstop", "é"} {
		if tuiWidth(s) != lipgloss.Width(s) {
			t.Fatalf("width of %q: %d want %d", s, tuiWidth(s), lipgloss.Width(s))
		}
	}
	if got := tuiPad("ab", 5); got != "ab   " {
		t.Fatalf("pad %q", got)
	}
	if got := tuiPad("中文", 6); lipgloss.Width(got) != 6 {
		t.Fatalf("pad wide %q", got)
	}
	if got := tuiPad("toolong", 4); lipgloss.Width(got) != 4 {
		t.Fatalf("pad must cut text wider than the column: %q", got)
	}
}

func TestTUIPager(t *testing.T) {
	var p tuiPager
	p.SetWidth(6)
	p.SetHeight(3)
	if p.View() != "      \n      \n      " {
		t.Fatalf("empty pager must fill its box: %q", p.View())
	}
	lines := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	p.SetContentLines(lines)
	p.ScrollDown(100)
	if p.YOffset() != 7 {
		t.Fatalf("scroll past the end: %d", p.YOffset())
	}
	p.ScrollUp(2)
	if p.YOffset() != 5 || p.TotalLineCount() != 10 {
		t.Fatalf("scroll up: %d", p.YOffset())
	}
	for _, c := range []struct {
		from int
		key  string
		want int
	}{
		{2, "pgup", 0}, {2, "pgdown", 5}, {5, "pgdown", 7}, {5, "j", 6}, {5, "down", 6},
		{5, "k", 4}, {5, "up", 4}, {5, "ctrl+d", 6}, {5, "ctrl+u", 4}, {5, "x", 5},
	} {
		p.SetYOffset(c.from)
		p, _ = p.Update(tuiKeyMsg(c.key))
		if p.YOffset() != c.want {
			t.Fatalf("%s from %d: offset %d want %d", c.key, c.from, p.YOffset(), c.want)
		}
	}
	// Shorter content pulls the position back so the last page stays full.
	p.SetContentLines(lines[:4])
	if p.YOffset() != 1 {
		t.Fatalf("offset after shrinking: %d", p.YOffset())
	}
	p.GotoTop()
	p.SetContentLines([]string{"abc", "wide line beyond", tuiAccent.Render("中文中文中文")})
	view := strings.Split(p.View(), "\n")
	for i, want := range []string{"abc   ", "wide l", "中文中"} {
		if termansi.Strip(view[i]) != want {
			t.Fatalf("row %d %q want %q", i, termansi.Strip(view[i]), want)
		}
	}
	if p.GetContent() != "abc\nwide line beyond\n"+tuiAccent.Render("中文中文中文") {
		t.Fatalf("content %q", p.GetContent())
	}
}
