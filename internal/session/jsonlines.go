package session

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
)

var ErrTruncatedJSONLine = errors.New("truncated final JSON line")

// JSONLines accepts a valid last record without a newline. A malformed record
// can be treated as a torn write only when it reaches EOF without a newline.
type JSONLines struct {
	scanner    *bufio.Scanner
	terminated bool
}

func NewJSONLines(r io.Reader, maxRecord int) *JSONLines {
	lines := &JSONLines{scanner: bufio.NewScanner(r)}
	lines.scanner.Buffer(make([]byte, min(maxRecord, 64<<10)), maxRecord)
	lines.scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		advance, token, err := bufio.ScanLines(data, atEOF)
		if token != nil {
			lines.terminated = data[advance-1] == '\n'
		}
		return advance, token, err
	})
	return lines
}

func (r *JSONLines) Next(record any) error {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return err
		}
		return io.EOF
	}
	err := json.Unmarshal(r.scanner.Bytes(), record)
	var syntax *json.SyntaxError
	if !r.terminated && errors.As(err, &syntax) && syntax.Error() == "unexpected end of JSON input" {
		return ErrTruncatedJSONLine
	}
	return err
}

func (r *JSONLines) Bytes() []byte { return r.scanner.Bytes() }
