package replay

import (
	"bufio"
	"io"
)

// rawRecorder sits under the HTTP bufio.Reader and keeps the exact bytes of
// the message being parsed. Saved evidence is these bytes, not a
// re-serialisation by net/http, which canonicalises header names, reorders
// headers, drops fields it cannot represent and rewrites line endings.
type rawRecorder struct {
	source io.Reader
	total  int64
	start  int64
	data   []byte
	limit  int
	active bool
}

func (r *rawRecorder) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.total += int64(n)
	if r.active && n > 0 && len(r.data) < r.limit {
		r.data = append(r.data, p[:min(n, r.limit-len(r.data))]...)
	}
	return n, err
}

// begin starts a message at the reader's current position. Bytes already
// buffered by br belong to the message (and possibly later ones).
func (r *rawRecorder) begin(br *bufio.Reader, limit int) {
	buffered, _ := br.Peek(br.Buffered())
	r.start = r.total - int64(len(buffered))
	r.limit = limit
	r.data = append(r.data[:0], buffered[:min(len(buffered), limit)]...)
	r.active = true
}

// end returns a copy of the bytes consumed since begin, capped at the limit,
// and whether the cap cut the message short.
func (r *rawRecorder) end(br *bufio.Reader) ([]byte, bool) {
	r.active = false
	consumed := r.total - int64(br.Buffered()) - r.start
	truncated := consumed > int64(len(r.data))
	size := min(consumed, int64(len(r.data)))
	if size < 0 {
		size = 0
	}
	raw := append([]byte(nil), r.data[:size]...)
	if cap(r.data) > 64<<10 {
		r.data = nil // do not retain a large body buffer per connection
	} else {
		r.data = r.data[:0]
	}
	return raw, truncated
}
