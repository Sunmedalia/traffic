package index

import (
	"bytes"
	"encoding/base64"
	"errors"
)

// RecordJSON rebuilds a stored transaction's JSON from its metadata object and
// the raw request and response bodies kept in BLOB columns. alerts, when it is
// a non-empty JSON array, is added as the alerts member. The metadata never
// carries these members itself, so they are appended rather than replaced.
// The bodies are encoded as base64 strings, which is how encoding/json writes
// a []byte, so the result decodes exactly like a record stored as one JSON.
func RecordJSON(data, request, response, alerts any) ([]byte, error) {
	meta := sqlBytes(data)
	req, resp, list := sqlBytes(request), sqlBytes(response), sqlBytes(alerts)
	if len(list) == 0 || bytes.Equal(list, []byte("[]")) {
		list = nil
	}
	if len(req) == 0 && len(resp) == 0 && list == nil {
		return meta, nil
	}
	end := len(meta) - 1
	if len(meta) < 2 || meta[0] != '{' || meta[end] != '}' {
		return nil, errors.New("traffic_record_json: metadata is not a JSON object")
	}
	size := len(meta) + base64.StdEncoding.EncodedLen(len(req)) + base64.StdEncoding.EncodedLen(len(resp)) + len(list) + 48
	out := make([]byte, 0, size)
	out = append(out, meta[:end]...)
	empty := len(bytes.TrimSpace(meta[1:end])) == 0
	member := func(name string) {
		if !empty {
			out = append(out, ',')
		}
		empty = false
		out = append(out, '"')
		out = append(out, name...)
		out = append(out, '"', ':')
	}
	for _, body := range []struct {
		name string
		data []byte
	}{{"request", req}, {"response", resp}} {
		if len(body.data) == 0 {
			continue
		}
		member(body.name)
		out = append(out, '"')
		out = base64.StdEncoding.AppendEncode(out, body.data)
		out = append(out, '"')
	}
	if list != nil {
		member("alerts")
		out = append(out, list...)
	}
	return append(out, '}'), nil
}

func sqlBytes(value any) []byte {
	switch v := value.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		return nil
	}
}
