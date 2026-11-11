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
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return "", ""
	}
	defer request.Body.Close()
	if !strings.EqualFold(request.Header.Get("Content-Encoding"), "gzip") {
		return "", ""
	}
	reader, err := gzip.NewReader(request.Body)
	if err != nil {
		return "", ""
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	view := "gzip-body"
	if len(body) > limit {
		body = body[:limit]
		view = "gzip-body-truncated"
	} else if err != nil {
		view = "gzip-body-incomplete"
	}
	return string(body), view
}
