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
	mu       sync.Mutex
	buffers  map[string][]byte
	contexts map[string]frameContext
}

func (f *Frames) feed(key string, payload []byte, head ...bool) ([][]byte, bool) {
	if f.buffers == nil {
		f.buffers = map[string][]byte{}
	}
	var total int
	for _, b := range f.buffers {
		total += len(b)
	}
	if total+len(payload) > 32<<20 {
		f.buffers = map[string][]byte{}
		return nil, true
	}
	old := f.buffers[key]
	if len(old) == 0 && len(payload) > 0 && payload[0] == '[' {
		return nil, false
	}
	b := append(old, payload...)
	if len(b) > max(requestLimit, responseLimit)+(64<<10) {
		delete(f.buffers, key)
		return [][]byte{b[:max(requestLimit, responseLimit)+(64<<10)]}, true
	}
	var frames [][]byte
	for len(b) > 0 {
		if !bytes.Contains(b, []byte("\r\n\r\n")) && !bytes.Contains(b, []byte("\n\n")) {
			break
		}
		reader := bytes.NewReader(b)
		br := bufio.NewReader(reader)
		var body io.ReadCloser
		var err error
		if bytes.HasPrefix(b, []byte("HTTP/")) {
			var r *http.Response
			var request *http.Request
			if len(head) > 0 && head[0] {
				request = &http.Request{Method: "HEAD"}
			}
			r, err = http.ReadResponse(br, request)
			if err == nil {
				body = r.Body
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
			delete(f.buffers, key)
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
		frames = append(frames, append([]byte(nil), b[:used]...))
		b = b[used:]
	}
	if len(f.buffers) > 4000 {
		f.buffers = map[string][]byte{}
	}
	if len(b) == 0 {
		delete(f.buffers, key)
	} else {
		f.buffers[key] = b
	}
	return frames, false
}
