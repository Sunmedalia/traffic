package session

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

func SafeText(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

func DecodedBody(raw []byte, limit int) (string, string) {
	buffer := bufio.NewReader(bytes.NewReader(raw))
	var body io.ReadCloser
	var headers http.Header
	if bytes.HasPrefix(raw, []byte("HTTP/")) {
		response, err := http.ReadResponse(buffer, nil)
		if err != nil {
			return "", ""
		}
		body, headers = response.Body, response.Header
	} else {
		request, err := http.ReadRequest(buffer)
		if err != nil {
			return "", ""
		}
		body, headers = request.Body, request.Header
	}
	defer body.Close()
	if !strings.EqualFold(headers.Get("Content-Encoding"), "gzip") {
		return "", ""
	}
	reader, err := gzip.NewReader(body)
	if err != nil {
		return "", ""
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	view := "gzip-body"
	if len(decoded) > limit {
		decoded = decoded[:limit]
		view = "gzip-body-truncated"
	} else if err != nil {
		view = "gzip-body-incomplete"
	}
	return string(decoded), view
}
