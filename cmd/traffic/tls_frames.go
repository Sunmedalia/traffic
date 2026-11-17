package main

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Frames waits for complete HTTP bodies before passing hook fragments to the parser.
type Frames struct {
	mu              sync.Mutex
	buffers         map[string][]byte
	contexts        map[string]frameContext
	buffered        int
	touched         map[string]uint64
	clock           uint64
	evicted         []evictedFrame
	http2           map[string]bool
	drains          map[string]int64
	byteLimit       int
	connectionLimit int
}

func (f *Frames) feed(key string, payload []byte, head ...bool) ([][]byte, bool) {
	if len(payload) == 0 {
		return nil, false
	}
	if f.buffers == nil {
		f.buffers = map[string][]byte{}
	}
	if f.touched == nil {
		f.touched = map[string]uint64{}
	}
	_, known := f.touched[key]
	f.clock++
	f.touched[key] = f.clock
	budget := f.byteLimit
	if budget == 0 {
		budget = 32 << 20
	}
	countLimit := f.connectionLimit
	if countLimit == 0 {
		countLimit = 4000
	}
	if len(payload) > budget {
		f.evicted = append(f.evicted, evictedFrame{key: key, data: f.buffers[key], meta: f.contexts[key]})
		f.remove(key)
		delete(f.http2, key)
		return nil, true
	}
	for !known && len(f.touched) > countLimit {
		oldest := ""
		var stamp uint64 = ^uint64(0)
		for candidate, value := range f.touched {
			if value < stamp {
				oldest, stamp = candidate, value
			}
		}
		f.evicted = append(f.evicted, evictedFrame{key: oldest, data: f.buffers[oldest], meta: f.contexts[oldest]})
		f.remove(oldest)
		delete(f.http2, oldest)
	}
	if f.http2[key] {
		return [][]byte{payload}, false
	}
	if remaining, ok := f.drains[key]; ok {
		consumed := min(int64(len(payload)), remaining)
		remaining -= consumed
		if remaining > 0 {
			f.drains[key] = remaining
			return nil, false
		}
		prefix := f.buffers[key]
		if bytes.HasPrefix(prefix, []byte("HTTP/")) && len(head) > 0 {
			head = head[1:]
		}
		f.remove(key)
		rest, gap := f.feed(key, payload[int(consumed):], head...)
		return append([][]byte{prefix}, rest...), gap
	}
	for f.buffered+len(payload) > budget && len(f.buffers) > 0 {
		oldest := ""
		var stamp uint64 = ^uint64(0)
		for candidate := range f.buffers {
			if f.touched[candidate] < stamp {
				oldest, stamp = candidate, f.touched[candidate]
			}
		}
		f.evicted = append(f.evicted, evictedFrame{key: oldest, data: f.buffers[oldest], meta: f.contexts[oldest]})
		f.remove(oldest)
	}
	old := f.buffers[key]
	if len(old) == 0 && len(payload) > 0 && payload[0] == '[' {
		return nil, false
	}
	b := append(old, payload...)
	if f.http2 == nil {
		f.http2 = map[string]bool{}
	}
	if f.http2[key] {
		return [][]byte{b}, false
	}
	if len(b) < len(h2Preface) && bytes.HasPrefix([]byte(h2Preface), b) {
		f.set(key, b)
		return nil, false
	}
	if bytes.HasPrefix(b, []byte(h2Preface)) || (len(b) >= 9 && b[0] == 0 && b[3] <= 9) {
		f.http2[key] = true
		f.remove(key)
		return [][]byte{b}, false
	}
	headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = bytes.Index(b, []byte("\n\n"))
	}
	if headerEnd > 32768 || (headerEnd < 0 && len(b) > 32768) {
		f.remove(key)
		return nil, true
	}
	if len(b) > max(requestLimit, responseLimit)+(64<<10) {
		cap := max(requestLimit, responseLimit) + (64 << 10)
		headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
		contentLength := int64(-1)
		if headerEnd >= 0 {
			br := bufio.NewReader(bytes.NewReader(b[:headerEnd+4]))
			if bytes.HasPrefix(b, []byte("HTTP/")) {
				if response, err := http.ReadResponse(br, nil); err == nil {
					contentLength = response.ContentLength
					if len(head) > 0 && head[0] {
						contentLength = 0
					}
				}
			} else {
				if request, err := http.ReadRequest(br); err == nil {
					contentLength = request.ContentLength
				}
			}
		}
		if headerEnd >= 0 && contentLength > int64(cap-headerEnd-4) {
			received := int64(len(b) - headerEnd - 4)
			prefix := append([]byte(nil), b[:cap]...)
			if received < contentLength {
				if f.drains == nil {
					f.drains = map[string]int64{}
				}
				f.drains[key] = contentLength - received
				f.set(key, prefix)
				return nil, false
			}
			end := headerEnd + 4 + int(contentLength)
			f.remove(key)
			rest, gap := f.feed(key, b[end:], head...)
			return append([][]byte{prefix}, rest...), gap
		}
		if contentLength < 0 || headerEnd < 0 {
			f.remove(key)
			return [][]byte{b[:cap]}, true
		}
	}
	var frames [][]byte
	responseIndex := 0
	for len(b) > 0 {
		if !bytes.Contains(b, []byte("\r\n\r\n")) && !bytes.Contains(b, []byte("\n\n")) {
			break
		}
		reader := bytes.NewReader(b)
		br := bufio.NewReader(reader)
		var body io.ReadCloser
		var err error
		advanceResponse := false
		if bytes.HasPrefix(b, []byte("HTTP/")) {
			var r *http.Response
			var request *http.Request
			if len(head) > responseIndex && head[responseIndex] {
				request = &http.Request{Method: "HEAD"}
			}
			r, err = http.ReadResponse(br, request)
			if err == nil {
				body = r.Body
				advanceResponse = r.StatusCode >= 200 || r.StatusCode == 101
			}
		} else {
			var r *http.Request
			r, err = http.ReadRequest(br)
			if err == nil {
				body = r.Body
			}
		}
		if err != nil {
			if strings.Contains(err.Error(), "EOF") {
				break
			}
			f.remove(key)
			return frames, true
		}
		_, err = io.Copy(io.Discard, body)
		body.Close()
		if err != nil {
			break
		}
		used := len(b) - reader.Len() - br.Buffered()
		if used <= 0 {
			break
		}
		if advanceResponse {
			responseIndex++
		}
		frames = append(frames, append([]byte(nil), b[:used]...))
		b = b[used:]
	}
	if len(b) == 0 {
		f.remove(key)
	} else {
		f.set(key, b)
	}
	return frames, false
}

// remove/set keep byte accounting constant-time. Call with f.mu held outside tests.
type evictedFrame struct {
	key  string
	data []byte
	meta frameContext
}

func (f *Frames) remove(key string) {
	f.buffered -= len(f.buffers[key])
	delete(f.buffers, key)
	delete(f.touched, key)
	delete(f.contexts, key)
	delete(f.drains, key)
}
func (f *Frames) set(key string, b []byte) {
	f.buffered += len(b) - len(f.buffers[key])
	f.buffers[key] = b
}
