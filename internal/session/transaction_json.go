package session

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"slices"
)

// DecodeTransaction returns what json.Unmarshal would decode from data into a
// zero Transaction, including its error.
//
// Stored records are mostly two base64 strings, the request and the response,
// and encoding/json walks them byte by byte several times. When data is an
// object whose top-level "request" and "response" members are plain base64
// strings, this decodes those directly and leaves only the small rest of the
// record to encoding/json. Anything it cannot prove equivalent (case or
// escape variants of those keys, repeated keys, whitespace around them,
// characters base64 skips but JSON forbids, invalid input) falls back to
// json.Unmarshal of the whole record.
func DecodeTransaction(data []byte) (Transaction, error) {
	if t, ok := decodeTransactionFast(data); ok {
		return t, nil
	}
	var t Transaction
	err := json.Unmarshal(data, &t)
	return t, err
}

// storedBody is one top-level "request" or "response" member in a record.
type storedBody struct {
	key, value, valueEnd, end int
}

func decodeTransactionFast(data []byte) (Transaction, bool) {
	var t Transaction
	request, response, ok := storedBodies(data)
	if !ok {
		return t, false
	}
	var cuts [][2]int
	for _, body := range []*storedBody{request, response} {
		if body == nil {
			continue
		}
		// The member must sit between '{' or ',' and ',' or '}', so removing
		// it together with one comma leaves valid JSON exactly when data is.
		// A leading comma must follow the end of a value and a trailing one
		// must precede the next key, or the cut could repair "{,m}" or "{m,}".
		before, after := data[body.key-1], data[body.end]
		switch {
		case before == ',':
			if body.key < 2 || !endsJSONValue(data[body.key-2]) {
				return t, false
			}
			cuts = append(cuts, [2]int{body.key - 1, body.end})
		case before == '{' && after == ',':
			if body.end+1 >= len(data) || data[body.end+1] != '"' {
				return t, false
			}
			cuts = append(cuts, [2]int{body.key, body.end + 1})
		case before == '{' && after == '}':
			cuts = append(cuts, [2]int{body.key, body.end})
		default:
			return t, false
		}
		if after != ',' && after != '}' {
			return t, false
		}
	}
	if len(cuts) == 0 {
		return t, false
	}
	slices.SortFunc(cuts, func(a, b [2]int) int { return a[0] - b[0] })
	rest := make([]byte, 0, 256)
	at := 0
	for _, cut := range cuts {
		if cut[0] > at {
			rest = append(rest, data[at:cut[0]]...)
		}
		at = max(at, cut[1])
	}
	rest = append(rest, data[at:]...)
	if json.Unmarshal(rest, &t) != nil || t.Request != nil || t.Response != nil {
		return Transaction{}, false
	}
	for _, field := range []struct {
		body *storedBody
		out  *[]byte
	}{{request, &t.Request}, {response, &t.Response}} {
		if field.body == nil {
			continue
		}
		decoded, ok := decodeStoredBody(data[field.body.value:field.body.valueEnd])
		if !ok {
			return Transaction{}, false
		}
		*field.out = decoded
	}
	return t, true
}

// endsJSONValue reports whether c can be the last byte of a JSON value:
// a string, object, array, number, true, false or null.
func endsJSONValue(c byte) bool {
	return c == '"' || c == '}' || c == ']' || c == 'e' || c == 'l' || c >= '0' && c <= '9'
}

// decodeStoredBody decodes a JSON string's content the way encoding/json
// decodes it into a []byte. Escapes and the CR/LF that base64 ignores but JSON
// forbids are left to encoding/json.
func decodeStoredBody(value []byte) ([]byte, bool) {
	if bytes.IndexByte(value, '\\') >= 0 || bytes.IndexByte(value, '\n') >= 0 || bytes.IndexByte(value, '\r') >= 0 {
		return nil, false
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	n, err := base64.StdEncoding.Decode(decoded, value)
	if err != nil {
		return nil, false
	}
	return decoded[:n], true
}

// storedBodies finds the top-level "request" and "response" members whose
// values are strings. It skips string contents with IndexByte instead of
// visiting every byte. Any top-level key that encoding/json could match to
// either field other than the exact lowercase spelling rejects the record.
func storedBodies(data []byte) (request, response *storedBody, ok bool) {
	if len(data) == 0 || data[0] != '{' {
		return nil, nil, false
	}
	depth := 0
	expectKey := false
	for i := 0; i < len(data); {
		switch data[i] {
		case '"':
			end, ok := skipJSONString(data, i)
			if !ok {
				return nil, nil, false
			}
			if depth != 1 || !expectKey {
				i = end
				continue
			}
			expectKey = false
			if end >= len(data) || data[end] != ':' {
				return nil, nil, false
			}
			key := data[i+1 : end-1]
			var slot **storedBody
			switch string(key) {
			case "request":
				slot = &request
			case "response":
				slot = &response
			default:
				if ambiguousBodyKey(key) {
					return nil, nil, false
				}
				i = end + 1
				continue
			}
			if *slot != nil {
				return nil, nil, false
			}
			value := end + 1
			if value >= len(data) || data[value] != '"' {
				// null or another type: encoding/json handles the record.
				return nil, nil, false
			}
			valueEnd, ok := skipJSONString(data, value)
			if !ok || valueEnd >= len(data) {
				return nil, nil, false
			}
			*slot = &storedBody{key: i, value: value + 1, valueEnd: valueEnd - 1, end: valueEnd}
			i = valueEnd
			continue
		case '{':
			depth++
			expectKey = depth == 1
		case '[':
			depth++
		case '}', ']':
			depth--
			if depth < 0 {
				return nil, nil, false
			}
		case ',':
			expectKey = depth == 1
		}
		i++
	}
	return request, response, depth == 0
}

// ambiguousBodyKey reports whether encoding/json might match key to the
// request or response field: an ASCII case variant, or a key whose escapes
// or non-ASCII letters (such as the Kelvin sign) could fold to one.
func ambiguousBodyKey(key []byte) bool {
	if bytes.EqualFold(key, []byte("request")) || bytes.EqualFold(key, []byte("response")) {
		return true
	}
	for _, c := range key {
		if c == '\\' || c >= 0x80 {
			return true
		}
	}
	return false
}

// skipJSONString returns the index just past the string starting at data[i].
func skipJSONString(data []byte, i int) (int, bool) {
	for j := i + 1; ; {
		k := bytes.IndexByte(data[j:], '"')
		if k < 0 {
			return 0, false
		}
		quote := j + k
		escapes := 0
		for p := quote - 1; p > i && data[p] == '\\'; p-- {
			escapes++
		}
		if escapes%2 == 0 {
			return quote + 1, true
		}
		j = quote + 1
	}
}
