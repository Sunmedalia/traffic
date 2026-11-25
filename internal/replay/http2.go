package replay

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const h2MemoryLimit = 16 << 20

type h2Message struct {
	headers          []hpack.HeaderField
	trailers         []hpack.HeaderField
	body             []byte
	ended, truncated bool
}
type h2Stream struct {
	request, response h2Message
	requestAt         time.Time
	responseAt        time.Time
	record            Transaction
}
type h2Direction struct {
	decoder      *hpack.Decoder
	buffer       []byte
	frameAt      time.Time
	block        []byte
	stream       uint32
	end          bool
	initialized  bool
	preface      bool
	allowedTable uint32
	tableSet     bool
	failed       bool
}
type h2Connection struct {
	directions [2]h2Direction
	streams    map[uint32]*h2Stream
	updated    time.Time
	meta       frameContext
	source     string
	bytes      int
}

// All HTTP/2 state is owned by h2mu, independent of HTTP/1 FIFO correlation.
// A discontinuity closes this state rather than reusing an uncertain HPACK table.
func (p *HTTPProcessor) closeHTTP2(key, reason string) {
	p.h2mu.Lock()
	defer p.h2mu.Unlock()
	p.closeHTTP2Locked(key, reason)
}
func (p *HTTPProcessor) closeHTTP2Locked(key, reason string) {
	c := p.h2[key]
	if c == nil {
		return
	}
	for id, stream := range c.streams {
		if len(stream.request.headers) > 0 {
			p.saveHTTP2(c, id, stream, true, reason)
		}
	}
	p.h2bytes -= c.bytes
	delete(p.h2, key)
}
func (p *HTTPProcessor) saveHTTP2(c *h2Connection, id uint32, s *h2Stream, incomplete bool, reason string) {
	t := s.record
	if t.ID == "" {
		t = Transaction{ID: fmt.Sprintf("h2-%x", serial.Add(1)), Time: s.requestAt, Source: c.source, Client: c.meta.client, LocalEndpoint: c.meta.local, PID: c.meta.pid, TargetID: c.meta.targetID, Backend: c.meta.backend, Service: c.meta.service, Connection: c.meta.connection, Protocol: "HTTP/2.0", StreamID: id}
		if t.Time.IsZero() {
			t.Time = time.Now().UTC()
		}
	}
	for _, f := range s.request.headers {
		switch f.Name {
		case ":method":
			t.Method = f.Value
		case ":path":
			t.URL = f.Value
		case ":authority":
			t.Host = f.Value
		}
	}
	if t.Method == "CONNECT" && t.URL == "" {
		t.URL = t.Host
	}
	t.RequestTrailers = http2Trailers(s.request.trailers)
	t.ResponseTrailers = http2Trailers(s.response.trailers)
	t.Request = renderHTTP2(s.request, t.Method+" "+t.URL+" HTTP/2.0")
	for _, f := range s.response.headers {
		if f.Name == ":status" {
			t.Status, _ = strconv.Atoi(f.Value)
		}
	}
	if len(s.response.headers) > 0 {
		t.Response = renderHTTP2(s.response, fmt.Sprintf("HTTP/2.0 %d %s", t.Status, http.StatusText(t.Status)))
		t.ResponseTime = s.responseAt
	}
	t.Truncated = s.request.truncated || s.response.truncated
	t.Incomplete = t.Incomplete || incomplete || c.meta.incomplete
	if reason != "" {
		t.IntegrityReasons = append(t.IntegrityReasons, reason)
	}
	if err := p.s.save(t); err != nil {
		p.s.fail(err)
	}
	// Bodies remain in the stream; do not retain a second copy in record.
	t.Request, t.Response = nil, nil
	s.record = t
}
func renderHTTP2(m h2Message, first string) []byte {
	var b bytes.Buffer
	b.WriteString(first + "\r\n")
	for _, f := range m.headers {
		if !strings.HasPrefix(f.Name, ":") && f.Name != "content-length" {
			fmt.Fprintf(&b, "%s: %s\r\n", f.Name, f.Value)
		}
	}
	// This is an analysis representation; original HTTP/2 frames remain evidence.
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(m.body))
	b.Write(m.body)
	return b.Bytes()
}
func (p *HTTPProcessor) ingestHTTP2(key string, request bool, data []byte, meta frameContext, source string) {
	p.h2mu.Lock()
	defer p.h2mu.Unlock()
	if p.h2 == nil {
		p.h2 = map[string]*h2Connection{}
	}
	now := meta.updated
	if now.IsZero() {
		now = meta.first
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	c := p.h2[key]
	if c == nil {
		if len(p.h2) >= 256 {
			var oldest string
			var selected *h2Connection
			for k, candidate := range p.h2 {
				idle := len(candidate.streams) == 0
				if selected == nil || (idle && len(selected.streams) != 0) ||
					(idle == (len(selected.streams) == 0) && candidate.updated.Before(selected.updated)) {
					oldest, selected = k, candidate
				}
			}
			p.s.gap("http2", oldest, "connection_limit", "connections", 1)
			p.closeHTTP2Locked(oldest, "connection_limit")
		}
		meta.connection = key
		c = &h2Connection{streams: map[uint32]*h2Stream{}, meta: meta, source: source}
		p.h2[key] = c
	}
	if request {
		c.meta = meta
		c.meta.connection = key
	}
	if now.After(c.updated) {
		c.updated = now
	}
	side := 0
	if !request {
		side = 1
	}
	d := &c.directions[side]
	if d.failed {
		return
	}
	fail := func(reason string) {
		p.s.gap("http2", key, reason, "connections", 1)
		for id, s := range c.streams {
			if len(s.request.headers) > 0 {
				p.saveHTTP2(c, id, s, true, reason)
			}
		}
		p.h2bytes -= c.bytes
		c.bytes = 0
		c.streams = map[uint32]*h2Stream{}
		for i := range c.directions {
			c.directions[i].failed = true
			c.directions[i].buffer = nil
			c.directions[i].block = nil
			c.directions[i].decoder = nil
		}
	}
	if meta.incomplete {
		fail("http2_capture_gap")
		return
	}
	if p.h2bytes+len(data) > h2MemoryLimit {
		fail("buffer_limit")
		return
	}
	frameAt := meta.first
	if frameAt.IsZero() {
		frameAt = now
	}
	if len(d.buffer) == 0 {
		d.frameAt = frameAt
	}
	d.buffer = append(d.buffer, data...)
	c.bytes += len(data)
	p.h2bytes += len(data)
	consume := func(n int) {
		d.buffer = d.buffer[n:]
		d.frameAt = frameAt
		c.bytes -= n
		p.h2bytes -= n
	}
	if !d.initialized {
		if request && !d.preface {
			if len(d.buffer) < len(h2Preface) {
				if !bytes.HasPrefix([]byte(h2Preface), d.buffer) {
					fail("http2_missing_preface")
				}
				return
			}
			if !bytes.HasPrefix(d.buffer, []byte(h2Preface)) {
				fail("http2_missing_preface")
				return
			}
			consume(len(h2Preface))
			d.preface = true
		}
		if len(d.buffer) < 9 {
			return
		}
		// The first frame in each direction must be SETTINGS. Otherwise HPACK
		// history may predate attachment, and decoding static-looking data is unsafe.
		if d.buffer[3] != 4 || binary.BigEndian.Uint32(d.buffer[5:9]) != 0 {
			fail("http2_missing_settings")
			return
		}
		d.initialized = true
		d.decoder = hpack.NewDecoder(4096, nil)
		d.decoder.SetMaxStringLength(32768)
		allowed := uint32(4096)
		if d.tableSet {
			allowed = d.allowedTable
		}
		d.decoder.SetAllowedMaxDynamicTableSize(allowed)
	}
	for len(d.buffer) >= 9 {
		size := int(d.buffer[0])<<16 | int(d.buffer[1])<<8 | int(d.buffer[2])
		if size > 1<<20 {
			fail("http2_frame_limit")
			return
		}
		if len(d.buffer) < size+9 {
			return
		}
		framer := http2.NewFramer(nil, bytes.NewReader(d.buffer[:size+9]))
		// The incremental direction owns CONTINUATION ordering across calls;
		// a short-lived Framer must not apply its empty connection history.
		framer.AllowIllegalReads = true
		frame, err := framer.ReadFrame()
		if err != nil {
			fail("http2_invalid_frame")
			return
		}
		if d.stream != 0 && (frame.Header().Type != http2.FrameContinuation || frame.Header().StreamID != d.stream) {
			fail("http2_invalid_continuation")
			return
		}
		id := frame.Header().StreamID
		stream := c.streams[id]
		if id != 0 && stream == nil && (frame.Header().Type == http2.FrameHeaders || frame.Header().Type == http2.FrameData || frame.Header().Type == http2.FrameContinuation) {
			if len(c.streams) >= 128 {
				fail("http2_stream_limit")
				return
			}
			stream = &h2Stream{}
			c.streams[id] = stream
		}
		headerEnd := false
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if err := f.ForeachSetting(func(setting http2.Setting) error {
				if err := setting.Valid(); err != nil {
					return err
				}
				if setting.ID == http2.SettingHeaderTableSize {
					if setting.Val > 65536 {
						return fmt.Errorf("HPACK table exceeds budget")
					}
					// SETTINGS constrains the opposite encoder / decoder direction.
					opposite := &c.directions[1-side]
					opposite.allowedTable = setting.Val
					opposite.tableSet = true
					if opposite.decoder != nil {
						opposite.decoder.SetAllowedMaxDynamicTableSize(setting.Val)
					}
				}
				return nil
			}); err != nil {
				fail("http2_settings_limit")
				return
			}
		case *http2.HeadersFrame:
			if request && stream.requestAt.IsZero() {
				stream.requestAt = d.frameAt
			}
			d.stream = id
			d.end = f.StreamEnded()
			fragment := f.HeaderBlockFragment()
			d.block = append(d.block, fragment...)
			c.bytes += len(fragment)
			p.h2bytes += len(fragment)
			headerEnd = f.HeadersEnded()
		case *http2.ContinuationFrame:
			if d.stream != id {
				fail("http2_invalid_continuation")
				return
			}
			fragment := f.HeaderBlockFragment()
			d.block = append(d.block, fragment...)
			c.bytes += len(fragment)
			p.h2bytes += len(fragment)
			headerEnd = f.HeadersEnded()
		case *http2.DataFrame:
			message := &stream.request
			limit := p.s.requestLimit()
			if !request {
				message = &stream.response
				limit = p.s.responseLimit()
			}
			if len(message.headers) == 0 || message.ended {
				fail("http2_data_without_headers")
				return
			}
			data := f.Data()
			n := min(len(data), max(0, limit-len(message.body)))
			message.body = append(message.body, data[:n]...)
			c.bytes += n
			p.h2bytes += n
			message.truncated = message.truncated || n < len(data)
			message.ended = f.StreamEnded()
			if !request && now.After(stream.responseAt) {
				stream.responseAt = now
			}
		case *http2.RSTStreamFrame:
			if stream != nil {
				if len(stream.request.headers) > 0 {
					p.saveHTTP2(c, id, stream, true, "http2_stream_reset")
				}
				p.releaseHTTP2Stream(c, id)
			}
		case *http2.GoAwayFrame:
			for streamID, s := range c.streams {
				if streamID > f.LastStreamID {
					p.saveHTTP2(c, streamID, s, true, "http2_goaway")
					p.releaseHTTP2Stream(c, streamID)
				}
			}
		case *http2.PushPromiseFrame:
			fail("http2_server_push_unsupported")
			return
		}
		if len(d.block) > 32768 {
			fail("http2_header_limit")
			return
		}
		if headerEnd {
			var fields []hpack.HeaderField
			total := 0
			d.decoder.SetEmitEnabled(true)
			d.decoder.SetEmitFunc(func(field hpack.HeaderField) {
				total += len(field.Name) + len(field.Value)
				if total > 32768 {
					d.decoder.SetEmitEnabled(false)
					return
				}
				fields = append(fields, field)
			})
			_, err := d.decoder.Write(d.block)
			if err == nil {
				err = d.decoder.Close()
			}
			if err != nil {
				fail("http2_hpack_unrecoverable")
				return
			}
			if total > 32768 {
				fail("http2_header_limit")
				return
			}
			message := &stream.request
			if !request {
				message = &stream.response
			}
			if !validHTTP2Fields(fields, request, len(message.headers) > 0) || message.ended || (len(message.headers) > 0 && !d.end) {
				fail("http2_invalid_headers")
				return
			}
			// Informational responses do not finish or replace the final response.
			informational := false
			for _, f := range fields {
				if f.Name == ":status" && len(f.Value) == 3 && f.Value[0] == '1' {
					informational = true
				}
			}
			if !informational {
				if len(message.headers) == 0 {
					message.headers = fields
					c.bytes += total
					p.h2bytes += total
				} else {
					message.trailers = fields
					c.bytes += total
					p.h2bytes += total
				}
				message.ended = d.end
				if !request && now.After(stream.responseAt) {
					stream.responseAt = now
				}
			}
			d.decoder.SetEmitFunc(func(hpack.HeaderField) {})
			c.bytes -= len(d.block)
			p.h2bytes -= len(d.block)
			d.block = nil
			d.stream = 0
			d.end = false
		}
		consume(size + 9)
		if stream != nil && c.streams[id] == stream && len(stream.request.headers) > 0 && (headerEnd || frame.Header().Flags.Has(http2.FlagDataEndStream)) {
			p.saveHTTP2(c, id, stream, false, "")
			if stream.request.ended && stream.response.ended {
				p.releaseHTTP2Stream(c, id)
			}
		}
		if p.h2bytes > h2MemoryLimit {
			fail("buffer_limit")
			return
		}
	}
	// Release consumed backing storage instead of retaining a large frame tail.
	if len(d.buffer) == 0 {
		d.buffer = nil
	}
}
func (p *HTTPProcessor) releaseHTTP2Stream(c *h2Connection, id uint32) {
	s := c.streams[id]
	if s == nil {
		return
	}
	n := len(s.request.body) + len(s.response.body)
	for _, m := range []h2Message{s.request, s.response} {
		for _, f := range append(m.headers, m.trailers...) {
			n += len(f.Name) + len(f.Value)
		}
	}
	c.bytes -= n
	p.h2bytes -= n
	delete(c.streams, id)
}
func (p *HTTPProcessor) processHTTP2Reader(br *bufio.Reader, key, client, source string, pid int, request bool, r io.Reader) {
	meta := frameContext{connection: key, client: client, pid: pid, first: time.Now().UTC()}
	if origin, ok := r.(interface {
		CaptureBackend() string
		CaptureService() string
	}); ok {
		meta.backend, meta.service = origin.CaptureBackend(), origin.CaptureService()
	}
	if identity, ok := r.(interface{ TargetIdentity() string }); ok {
		meta.targetID = identity.TargetIdentity()
	}
	if timed, ok := r.(interface{ CaptureTime() time.Time }); ok {
		meta.first = timed.CaptureTime()
	}
	if local, ok := r.(interface{ LocalEndpoint() string }); ok {
		meta.local = local.LocalEndpoint()
	}
	if request {
		b := make([]byte, len(h2Preface))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		p.ingestHTTP2(key, true, b, meta, source)
	}
	for {
		if _, err := br.Peek(1); err != nil {
			return
		}
		meta.first = time.Now().UTC()
		if timed, ok := r.(interface{ CaptureTime() time.Time }); ok {
			meta.first = timed.CaptureTime()
		}
		header := make([]byte, 9)
		_, err := io.ReadFull(br, header)
		if err != nil {
			if err != io.EOF {
				p.closeHTTP2(key, "http2_partial_frame")
			}
			return
		}
		size := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		if size > 1<<20 {
			p.s.gap("http2", key, "http2_frame_limit", "frames", 1)
			p.closeHTTP2(key, "http2_frame_limit")
			return
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(br, payload); err != nil {
			p.closeHTTP2(key, "http2_partial_frame")
			return
		}
		if state, ok := r.(interface{ Incomplete() bool }); ok {
			meta.incomplete = state.Incomplete()
		}
		meta.updated = meta.first
		if stream, ok := r.(*queuedStream); ok {
			meta.updated = stream.latest
		}
		p.ingestHTTP2(key, request, append(header, payload...), meta, source)
	}
}

// Keep deterministic ordering when finishing sessions, including reset streams.
func (p *HTTPProcessor) finishHTTP2() {
	p.h2mu.Lock()
	defer p.h2mu.Unlock()
	keys := make([]string, 0, len(p.h2))
	for key := range p.h2 {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p.closeHTTP2Locked(key, "http2_unfinished_at_stop")
	}
}

func http2Trailers(fields []hpack.HeaderField) map[string][]string {
	if len(fields) == 0 {
		return nil
	}
	headers := map[string][]string{}
	for _, field := range fields {
		headers[field.Name] = append(headers[field.Name], field.Value)
	}
	return headers
}
func validHTTP2Fields(fields []hpack.HeaderField, request, trailers bool) bool {
	regular := false
	pseudo := map[string]string{}
	for _, field := range fields {
		if !httpguts.ValidHeaderFieldValue(field.Value) || field.Name != strings.ToLower(field.Name) {
			return false
		}
		if strings.HasPrefix(field.Name, ":") {
			if regular || trailers {
				return false
			}
			if _, exists := pseudo[field.Name]; exists {
				return false
			}
			if request {
				switch field.Name {
				case ":method", ":path", ":scheme", ":authority", ":protocol":
				default:
					return false
				}
			} else if field.Name != ":status" {
				return false
			}
			pseudo[field.Name] = field.Value
		} else {
			regular = true
			if !httpguts.ValidHeaderFieldName(field.Name) {
				return false
			}
		}
	}
	if trailers {
		return true
	}
	if request {
		return pseudo[":method"] != "" && (pseudo[":path"] != "" || pseudo[":method"] == "CONNECT")
	}
	status, err := strconv.Atoi(pseudo[":status"])
	return err == nil && len(pseudo[":status"]) == 3 && status >= 100 && status <= 599
}
