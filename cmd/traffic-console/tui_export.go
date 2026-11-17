package main

// Evidence export dialog.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

type tuiExport struct {
	id, label, state string
	input            textinput.Model
	err              string
	running          bool
}

func (m *tuiModel) openExport() tea.Cmd {
	row, ok := m.currentRow()
	if !ok {
		m.flash = "没有选中的请求"
		return nil
	}
	input := textinput.New()
	input.SetVirtualCursor(true)
	input.CharLimit = 4096
	input.SetWidth(max(10, m.width-6))
	input.SetValue("./evidence-" + tuiFileSafe(row.ID) + ".zip")
	m.export = &tuiExport{id: row.ID, label: tuiLine(row.Method + " " + row.URL), state: m.snapshot.Stats.State, input: input}
	return m.export.input.Focus()
}
func tuiFileSafe(s string) string {
	safe := strings.Map(func(r rune) rune {
		if r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == '_') {
			return r
		}
		return '_'
	}, s)
	if len(safe) > 64 {
		safe = safe[:64]
	}
	return safe
}
func (e *tuiExport) view() string {
	lines := []string{tuiAccent.Render("导出证据"), "", tuiMuted.Render("请求  ") + e.label, "", tuiMuted.Render("保存到"), e.input.View(), "",
		tuiMuted.Render("包含请求、响应、事件 JSON、关联 PCAP 和 SHA-256 清单。目标文件必须不存在。")}
	if e.state == "running" {
		lines = append(lines, tuiWarn.Render("采集仍在进行。导出需要采集锁，请先停止采集。"))
	}
	if e.running {
		lines = append(lines, "", tuiAccent.Render("正在导出…"))
	}
	if e.err != "" {
		lines = append(lines, "", tuiDanger.Render(e.err))
	}
	return strings.Join(lines, "\n")
}
func (m *tuiModel) updateExport(msg tea.KeyPressMsg) tea.Cmd {
	e := m.export
	switch msg.String() {
	case "esc":
		m.export = nil
		return nil
	case "enter":
		if e.running {
			return nil
		}
		path := strings.TrimSpace(e.input.Value())
		if path == "" {
			e.err = "请输入保存路径"
			return nil
		}
		if path == "~" || strings.HasPrefix(path, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				path = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
			}
		}
		if absolute, err := filepath.Abs(path); err == nil {
			path = absolute
		}
		e.running, e.err = true, ""
		store, id := m.store, e.id
		return func() tea.Msg {
			var b []byte
			if err := store.db.QueryRow("SELECT data FROM requests WHERE id=?", id).Scan(&b); err != nil {
				return tuiExported{ID: id, Err: err}
			}
			var t Transaction
			if err := json.Unmarshal(b, &t); err != nil {
				return tuiExported{ID: id, Err: err}
			}
			if err := exportEvidence(store, t, b, path); err != nil {
				return tuiExported{ID: id, Err: err}
			}
			var size int64
			if info, err := os.Stat(path); err == nil {
				size = info.Size()
			}
			return tuiExported{ID: id, Path: path, Size: size}
		}
	}
	var cmd tea.Cmd
	e.input, cmd = e.input.Update(msg)
	return cmd
}
func tuiExportError(err error) string {
	switch {
	case errors.Is(err, errCaptureRunning):
		return "导出失败：采集仍在进行，停止采集后再导出"
	case errors.Is(err, fs.ErrExist):
		return "导出失败：目标文件已存在，请换一个文件名"
	case errors.Is(err, sql.ErrNoRows):
		return "导出失败：该记录已被保留期清理"
	}
	return "导出失败：" + cleanTUIText(err.Error())
}
