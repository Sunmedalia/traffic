package main

// The decoder tab ports the web decoding tool. Nothing is decoded
// automatically: each step is an explicit choice that can be chained and
// undone, and steps work on bytes so binary results survive until shown.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

const tuiDecodeInput = 1 << 20
const tuiDecodeOutput = 16 << 20

type tuiDecodeFunc func([]byte) ([]byte, error)

type tuiDecodeKind struct {
	label, title string
	run          tuiDecodeFunc
	// gzip only applies to compressed bytes; trying it is the check.
	compressed bool
}

var tuiHTMLNamed = map[string]string{"amp": "&", "lt": "<", "gt": ">", "quot": `"`, "apos": "'", "nbsp": " ", "sol": "/", "colon": ":", "lpar": "(", "rpar": ")", "equals": "=", "semi": ";", "comma": ",", "period": ".", "excl": "!", "num": "#", "percnt": "%", "plus": "+", "lsqb": "[", "rsqb": "]", "lcub": "{", "rcub": "}", "bsol": `\`, "grave": "`", "Tab": "\t", "NewLine": "\n"}
var tuiHTMLEntity = regexp.MustCompile(`(?i)&(#x[0-9a-f]+|#\d+|[a-z]+);?`)
var tuiEscapeBrace = regexp.MustCompile(`(?i)\\u\{([0-9a-f]{1,6})\}`)
var tuiEscapeU = regexp.MustCompile(`(?i)(?:\\|%)u([0-9a-f]{4})`)
var tuiEscapeX = regexp.MustCompile(`(?i)\\x([0-9a-f]{2})`)
var tuiEscapeChar = regexp.MustCompile(`\\([nrtbf0'"\\/])`)

func tuiCodePoint(v int64) string {
	if v > 0 && v <= 0x10ffff {
		return string(rune(v))
	}
	return "�"
}

func tuiPercent(plus bool) tuiDecodeFunc {
	return func(in []byte) ([]byte, error) {
		out := make([]byte, 0, len(in))
		for i := 0; i < len(in); i++ {
			switch c := in[i]; {
			case c == '%' && i+2 < len(in) && isHex(in[i+1]) && isHex(in[i+2]):
				b, _ := hex.DecodeString(string(in[i+1 : i+3]))
				out = append(out, b[0])
				i += 2
			case plus && c == '+':
				out = append(out, ' ')
			default:
				out = append(out, c)
			}
		}
		return out, nil
	}
}
func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

var tuiBase64Text = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

func tuiBase64(in []byte) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		case '-':
			return '+'
		case '_':
			return '/'
		}
		return r
	}, string(in))
	if clean == "" || !tuiBase64Text.MatchString(clean) {
		return nil, errors.New("不是有效的 Base64")
	}
	clean = strings.TrimRight(clean, "=")
	if len(clean)%4 == 1 {
		return nil, errors.New("不是有效的 Base64")
	}
	// The default decoder accepts non-zero trailing bits, as the browser's atob does.
	out, err := base64.RawStdEncoding.DecodeString(clean)
	if err != nil {
		return nil, errors.New("不是有效的 Base64")
	}
	return out, nil
}

var tuiHexNoise = regexp.MustCompile(`(?i)0x|\\x|%|[\s:,-]`)

func tuiHex(in []byte) ([]byte, error) {
	clean := tuiHexNoise.ReplaceAllString(string(in), "")
	out, err := hex.DecodeString(clean)
	if clean == "" || err != nil {
		return nil, errors.New("不是有效的十六进制")
	}
	return out, nil
}

func tuiHTML(in []byte) ([]byte, error) {
	return []byte(tuiHTMLEntity.ReplaceAllStringFunc(string(in), func(all string) string {
		body := tuiHTMLEntity.FindStringSubmatch(all)[1]
		if body[0] == '#' {
			var v int64
			var err error
			if len(body) > 1 && (body[1] == 'x' || body[1] == 'X') {
				v, err = strconv.ParseInt(body[2:], 16, 64)
			} else {
				v, err = strconv.ParseInt(body[1:], 10, 64)
			}
			if err != nil {
				return "�"
			}
			return tuiCodePoint(v)
		}
		if named, ok := tuiHTMLNamed[body]; ok {
			return named
		}
		return all
	})), nil
}

func tuiUnicode(in []byte) ([]byte, error) {
	s := string(in)
	s = tuiEscapeBrace.ReplaceAllStringFunc(s, func(all string) string {
		v, _ := strconv.ParseInt(tuiEscapeBrace.FindStringSubmatch(all)[1], 16, 64)
		return tuiCodePoint(v)
	})
	s = tuiEscapeU.ReplaceAllStringFunc(s, func(all string) string {
		v, _ := strconv.ParseInt(tuiEscapeU.FindStringSubmatch(all)[1], 16, 64)
		return string(rune(v))
	})
	s = tuiEscapeX.ReplaceAllStringFunc(s, func(all string) string {
		v, _ := strconv.ParseInt(tuiEscapeX.FindStringSubmatch(all)[1], 16, 64)
		return string(rune(v))
	})
	s = tuiEscapeChar.ReplaceAllStringFunc(s, func(all string) string {
		switch c := all[1]; c {
		case 'n':
			return "\n"
		case 'r':
			return "\r"
		case 't':
			return "\t"
		case 'b':
			return "\b"
		case 'f':
			return "\f"
		case '0':
			return "\x00"
		default:
			return string(c)
		}
	})
	return []byte(s), nil
}

func tuiJWT(in []byte) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(string(in)), ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, errors.New("不是 JWT")
	}
	part := func(text string) (string, error) {
		raw, err := tuiBase64([]byte(text))
		if err != nil {
			return "", err
		}
		var out bytes.Buffer
		if err := json.Indent(&out, raw, "", "  "); err != nil {
			return "", errors.New("不是 JWT")
		}
		return out.String(), nil
	}
	head, err := part(parts[0])
	if err != nil {
		return nil, err
	}
	payload, err := part(parts[1])
	if err != nil {
		return nil, err
	}
	text := "// 头部\n" + head + "\n// 载荷\n" + payload
	if len(parts) == 3 && parts[2] != "" {
		text += "\n// 签名（未校验）\n" + parts[2]
	}
	return []byte(text), nil
}

func tuiInflate(in []byte) ([]byte, error) {
	readers := []func() (io.Reader, error){}
	switch {
	case len(in) > 1 && in[0] == 0x1f && in[1] == 0x8b:
		readers = append(readers, func() (io.Reader, error) { return gzip.NewReader(bytes.NewReader(in)) })
	case len(in) > 0 && in[0] == 0x78:
		readers = append(readers, func() (io.Reader, error) { return zlib.NewReader(bytes.NewReader(in)) })
		fallthrough
	default:
		readers = append(readers, func() (io.Reader, error) { return flate.NewReader(bytes.NewReader(in)), nil })
	}
	for _, open := range readers {
		r, err := open()
		if err != nil {
			continue
		}
		out, err := io.ReadAll(io.LimitReader(r, tuiDecodeOutput+1))
		if len(out) > tuiDecodeOutput {
			return nil, errors.New("解压结果不能超过 16 MiB")
		}
		if err == nil && len(out) > 0 {
			return out, nil
		}
	}
	return nil, errors.New("不是可解压的数据")
}

var tuiDecoders = []tuiDecodeKind{
	{label: "URL", title: "百分号解码，+ 视为空格", run: tuiPercent(true)},
	{label: "URL（保留 +）", title: "百分号解码，+ 保持原样（路径、Cookie 常用）", run: tuiPercent(false)},
	{label: "Base64", title: "标准或 URL 安全 Base64，自动补齐 =", run: tuiBase64},
	{label: "Hex", title: `十六进制，可带 0x、\x、% 或空格分隔`, run: tuiHex},
	{label: "HTML 实体", title: "&lt; &#60; &#x3c; 等", run: tuiHTML},
	{label: "Unicode / JS 转义", title: `\uXXXX、\u{…}、%uXXXX、\xHH、\n 等`, run: tuiUnicode},
	{label: "JWT", title: "解出 JWT 的头部与载荷（不校验签名）", run: tuiJWT},
	{label: "Gzip / Deflate", title: "解压 gzip、zlib 或原始 deflate 字节", run: tuiInflate, compressed: true},
}

// applies is the cheap check that marks decoders worth trying, as the web
// page highlights them.
func (d tuiDecodeKind) applies(in []byte) bool {
	if d.compressed {
		return len(in) > 1 && (in[0] == 0x1f && in[1] == 0x8b || in[0] == 0x78 && bytes.IndexByte([]byte{0x01, 0x5e, 0x9c, 0xda}, in[1]) >= 0)
	}
	out, err := d.run(in)
	return err == nil && !bytes.Equal(out, in)
}

func tuiLooksBinary(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	odd, total := 0, 0
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		total++
		if r == utf8.RuneError || r < 32 && r != '\t' && r != '\n' && r != '\r' {
			odd++
		}
	}
	return odd*10 > total
}

func tuiHexDump(b []byte) string {
	lines := []string{}
	for at := 0; at < min(len(b), 65536); at += 16 {
		row := b[at:min(len(b), at+16)]
		hexes := make([]string, len(row))
		text := make([]byte, len(row))
		for i, c := range row {
			hexes[i] = fmt.Sprintf("%02x", c)
			text[i] = '.'
			if c >= 32 && c < 127 {
				text[i] = c
			}
		}
		lines = append(lines, fmt.Sprintf("%08x  %-47s  %s", at, strings.Join(hexes, " "), text))
	}
	if len(b) > 65536 {
		lines = append(lines, fmt.Sprintf("… 共 %s 字节，仅显示前 64 KiB", tuiCount(uint64(len(b)))))
	}
	return strings.Join(lines, "\n")
}

// tuiMessage is an HTTP message split into its start line, headers and body.
type tuiMessage struct {
	start   string
	headers [][2]string
	body    string
}

func tuiSplitHTTP(text string) tuiMessage {
	head, body, found := strings.Cut(text, "\r\n\r\n")
	if !found {
		head, body, found = strings.Cut(text, "\n\n")
	}
	if !found {
		body = ""
	}
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	message := tuiMessage{start: lines[0], body: body}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			message.headers = append(message.headers, [2]string{line, "\x00"})
			continue
		}
		message.headers = append(message.headers, [2]string{name, strings.TrimSpace(value)})
	}
	return message
}
func (t tuiMessage) header(name string) string {
	for _, h := range t.headers {
		if strings.EqualFold(h[0], name) && h[1] != "\x00" {
			return h[1]
		}
	}
	return ""
}

// tuiPairs splits name=value lists as typed, without decoding.
func tuiPairs(text string, separator *regexp.Regexp) [][2]string {
	if text == "" {
		return nil
	}
	result := [][2]string{}
	for _, part := range separator.Split(text, -1) {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		result = append(result, [2]string{name, value})
		if len(result) == 500 {
			break
		}
	}
	return result
}

var tuiAmp = regexp.MustCompile(`&`)
var tuiSemi = regexp.MustCompile(`;\s*`)

type tuiDecodeSource struct{ label, value string }

// decodeSources lists the values a user may want to decode, as the web page does.
func (m tuiModel) decodeSources() []tuiDecodeSource {
	t := m.snapshot.Detail
	if t == nil {
		return nil
	}
	sources := []tuiDecodeSource{{"完整 URL", t.URL}}
	url, _, _ := strings.Cut(t.URL, "#")
	path, query, hasQuery := strings.Cut(url, "?")
	if hasQuery && query != "" {
		sources = append(sources, tuiDecodeSource{"路径", path}, tuiDecodeSource{"查询字符串", query})
		for _, p := range tuiPairs(query, tuiAmp) {
			sources = append(sources, tuiDecodeSource{"查询参数 " + p[0], p[1]})
		}
	}
	if len(t.Request) > 0 {
		message := tuiSplitHTTP(m.requestText())
		for _, p := range tuiPairs(message.header("cookie"), tuiSemi) {
			sources = append(sources, tuiDecodeSource{"Cookie " + p[0], p[1]})
		}
		if strings.Contains(strings.ToLower(message.header("content-type")), "x-www-form-urlencoded") {
			for _, p := range tuiPairs(message.body, tuiAmp) {
				sources = append(sources, tuiDecodeSource{"表单参数 " + p[0], p[1]})
			}
		}
		if message.body != "" {
			sources = append(sources, tuiDecodeSource{"请求正文", message.body})
		}
		for _, name := range []string{"authorization", "referer", "user-agent", "x-forwarded-for"} {
			if value := message.header(name); value != "" {
				sources = append(sources, tuiDecodeSource{"请求头 " + name, value})
			}
		}
	}
	for _, a := range t.Alerts {
		sources = append(sources, tuiDecodeSource{"命中片段 " + a.Rule, a.Match})
	}
	result := sources[:0]
	for _, s := range sources {
		if s.value != "" {
			result = append(result, s)
		}
	}
	return result
}

type tuiDecodeStep struct {
	label string
	data  []byte
}
type tuiDecoder struct {
	id, label string
	source    int // index into the sources, -1 for manual input
	input     string
	steps     []tuiDecodeStep
	hex       bool
	err       string
	picking   bool
	pick      int
	editor    *textinput.Model
}

// capturing reports a picker or text input that owns the keyboard.
func (d *tuiDecoder) capturing() bool { return d.picking || d.editor != nil }
func (d *tuiDecoder) last() []byte    { return d.steps[len(d.steps)-1].data }
func (d *tuiDecoder) reset(label, value string, source int) {
	if len(value) > tuiDecodeInput {
		value = value[:tuiDecodeInput]
	}
	d.label, d.input, d.source = label, value, source
	d.steps = []tuiDecodeStep{{"原文", []byte(value)}}
	d.hex, d.err = false, ""
}

// currentDecoder starts on the first query parameter, or the URL, of the open record.
func (m *tuiModel) currentDecoder() *tuiDecoder {
	if m.decoder != nil && m.decoder.id == m.detailID {
		return m.decoder
	}
	sources := m.decodeSources()
	m.decoder = &tuiDecoder{id: m.detailID}
	pick := 0
	for i, s := range sources {
		if strings.HasPrefix(s.label, "查询参数") {
			pick = i
			break
		}
	}
	if len(sources) == 0 {
		m.decoder.reset("完整 URL", "", -1)
	} else {
		m.decoder.reset(sources[pick].label, sources[pick].value, pick)
	}
	return m.decoder
}

// openDecoderFor opens the decoder tab on a source: the URL, or the first alert
// match from the evidence tab.
func (m *tuiModel) openDecoderFor(label string) {
	if m.snapshot.Detail == nil || m.snapshot.Detail.ID != m.detailID {
		m.flash = "详情仍在加载"
		return
	}
	d := m.currentDecoder()
	sources := m.decodeSources()
	if label == "" {
		label = "完整 URL"
		if m.activeDetailTab() == detailAlerts && len(m.snapshot.Detail.Alerts) > 0 {
			label = "命中片段 " + m.snapshot.Detail.Alerts[0].Rule
		}
	}
	for i, s := range sources {
		if s.label == label {
			d.reset(s.label, s.value, i)
			break
		}
	}
	m.setDetailTab(detailDecoder)
}

func (m *tuiModel) applyDecoder(kind tuiDecodeKind) {
	d := m.currentDecoder()
	out, err := kind.run(d.last())
	switch {
	case err != nil:
		d.err = kind.label + "：" + err.Error()
	case bytes.Equal(out, d.last()):
		d.err = kind.label + "：解码后内容没有变化"
	default:
		d.steps = append(d.steps, tuiDecodeStep{kind.label, out})
		d.err = ""
		d.hex = tuiLooksBinary(out)
	}
	m.updateContent()
}

// updateDecoderKey handles the decoder tab when no picker or input is open.
func (m *tuiModel) updateDecoderKey(key string) (tea.Cmd, bool) {
	d := m.currentDecoder()
	sources := m.decodeSources()
	switch key {
	case "left", "right", "h", "l":
		if len(sources) == 0 {
			return nil, true
		}
		step := 1
		if key == "left" || key == "h" {
			step = -1
		}
		next := (d.source + step + len(sources)) % len(sources)
		if d.source < 0 && step < 0 {
			next = len(sources) - 1
		}
		d.reset(sources[next].label, sources[next].value, next)
		m.updateContent()
		return nil, true
	case "enter":
		d.picking, d.pick, d.err = true, 0, ""
		for i, kind := range tuiDecoders {
			if kind.applies(d.last()) {
				d.pick = i
				break
			}
		}
		m.updateContent()
		return nil, true
	case "backspace", "u":
		if len(d.steps) > 1 {
			d.steps = d.steps[:len(d.steps)-1]
			d.err = ""
			d.hex = tuiLooksBinary(d.last())
			m.updateContent()
		}
		return nil, true
	case "X":
		d.hex = !d.hex
		m.updateContent()
		return nil, true
	case "w":
		input := textinput.New()
		input.SetVirtualCursor(true)
		input.CharLimit = tuiDecodeInput
		input.Prompt = "解码 > "
		input.Placeholder = "粘贴或输入要解码的文字"
		input.SetWidth(max(10, m.width-12))
		input.SetValue(d.input)
		d.editor = &input
		m.updateContent()
		return d.editor.Focus(), true
	}
	return nil, false
}

// updateDecoderModal drives the decoder picker and the manual input.
func (m *tuiModel) updateDecoderModal(msg tea.KeyPressMsg) tea.Cmd {
	d := m.decoder
	key := msg.String()
	if d.editor != nil {
		switch key {
		case "esc":
			d.editor = nil
		case "enter":
			d.reset("手动输入", d.editor.Value(), -1)
			d.editor = nil
		default:
			var cmd tea.Cmd
			*d.editor, cmd = d.editor.Update(msg)
			return cmd
		}
		m.updateContent()
		return nil
	}
	switch key {
	case "esc":
		d.picking = false
	case "up", "k":
		d.pick = (d.pick + len(tuiDecoders) - 1) % len(tuiDecoders)
	case "down", "j", "tab":
		d.pick = (d.pick + 1) % len(tuiDecoders)
	case "enter":
		d.picking = false
		m.applyDecoder(tuiDecoders[d.pick])
		return nil
	}
	m.updateContent()
	return nil
}

func (m tuiModel) decoderContent() string {
	d := m.decoder
	if d == nil || d.id != m.detailID {
		return "正在准备解码工具…"
	}
	sources := m.decodeSources()
	var b strings.Builder
	position := "手动输入"
	if d.source >= 0 {
		position = fmt.Sprintf("%d/%d", d.source+1, len(sources))
	}
	fmt.Fprintf(&b, "%s ‹ %s › %s · %s 字节  %s\n", tuiMuted.Render("来源"), tuiAccent.Render(tuiLine(d.label)), tuiMuted.Render(position), tuiCount(uint64(len(d.input))), tuiMuted.Render("←→ 换来源 · w 手动输入"))
	if d.editor != nil {
		b.WriteString(d.editor.View() + "\n")
	} else {
		input := d.input
		if len(input) > 600 {
			input = input[:600] + "…"
		}
		b.WriteString(tuiMuted.Render(tuiLine(input)) + "\n")
	}
	chain := []string{}
	for i, step := range d.steps {
		if i == len(d.steps)-1 {
			chain = append(chain, tuiAccent.Render("["+step.label+"]"))
		} else {
			chain = append(chain, step.label)
		}
	}
	fmt.Fprintf(&b, "%s %s  %s\n", tuiMuted.Render("步骤"), strings.Join(chain, tuiMuted.Render(" → ")), tuiMuted.Render("Enter 选择解码方式 · Backspace 撤销 · X 十六进制"))
	if d.picking {
		b.WriteString("\n" + tuiAccent.Render("解码为") + tuiMuted.Render("  ↑↓ 选择 · Enter 解码 · Esc 取消 · ✓ 表示当前结果可以这样解码") + "\n")
		for i, kind := range tuiDecoders {
			mark := "  "
			if kind.applies(d.last()) {
				mark = tuiGood.Render("✓ ")
			}
			line := mark + tuiCell(kind.label, 20) + tuiMuted.Render(kind.title)
			if i == d.pick {
				line = tuiSelected.Render("▸ " + tuiCell(kind.label, 20) + kind.title)
			}
			b.WriteString(line + "\n")
		}
	}
	if d.err != "" {
		b.WriteString(tuiDanger.Render(tuiLine(d.err)) + "\n")
	}
	title := "原文"
	if len(d.steps) > 1 {
		title = fmt.Sprintf("结果 · %d 步", len(d.steps)-1)
	}
	out := d.last()
	b.WriteString("\n" + tuiBold.Render(title) + tuiMuted.Render(fmt.Sprintf(" · %s 字节", tuiCount(uint64(len(out))))))
	if tuiLooksBinary(out) {
		b.WriteString(tuiWarn.Render(" · 含二进制"))
	}
	if d.hex {
		b.WriteString(tuiMuted.Render(" · 十六进制"))
	}
	b.WriteString("\n")
	if d.hex {
		b.WriteString(tuiHexDump(out))
	} else {
		b.WriteString(m.highlightBody(cleanTUIText(strings.ToValidUTF8(string(out), "�"))))
	}
	b.WriteString("\n\n" + tuiMuted.Render("解码只在本地进行，不改动采集数据。Y 复制当前结果。"))
	return b.String()
}

// copyContent sends the visible tab's text to the clipboard, like the web 复制 button.
func (m *tuiModel) copyContent() tea.Cmd {
	t := m.snapshot.Detail
	if t == nil || t.ID != m.detailID {
		m.flash = "详情仍在加载"
		return nil
	}
	text, label := "", ""
	switch m.activeDetailTab() {
	case detailRequest:
		text, label = m.requestText(), "请求"
		if m.msgLayout != layoutSingle && len(t.Response) > 0 {
			text, label = text+"\n\n"+m.responseText(), "请求和响应"
		}
	case detailResponse:
		text, label = m.responseText(), "响应"
	case detailDecoded:
		parts := []string{}
		for _, s := range []string{m.bodies.request, m.bodies.response} {
			if s != "" {
				parts = append(parts, s)
			}
		}
		text, label = strings.Join(parts, "\n\n"), "解压正文"
	case detailDecoder:
		if m.decoder != nil {
			text = strings.ToValidUTF8(string(m.decoder.last()), "�")
		}
		label = "解码结果"
	case detailAlerts:
		matches := []string{}
		for _, a := range t.Alerts {
			matches = append(matches, a.Rule+": "+a.Match)
		}
		text, label = strings.Join(matches, "\n"), "命中片段"
	}
	if text == "" {
		m.flash = "当前标签没有可复制的内容"
		return nil
	}
	m.flash = fmt.Sprintf("已发送%s到剪贴板（%s 字节，终端不支持 OSC 52 时请手动选取）", label, tuiCount(uint64(len(text))))
	return tea.SetClipboard(text)
}
