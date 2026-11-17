package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
)

// Compare the same request/response flow using complete TLS frames and streaming
// readers. It includes parsing, indexing and response restoration, not just the
// allocation of bufio.Reader itself.
func BenchmarkHTTPReaderBuffers(b *testing.B) {
	if err := loadRules(""); err != nil {
		b.Fatal(err)
	}
	previous := noDetect
	noDetect = true
	defer func() { noDetect = previous }()
	body := bytes.Repeat([]byte("x"), 1024)
	request := append([]byte(fmt.Sprintf("POST /benchmark HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	response := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	for _, framed := range []bool{false, true} {
		name := "streaming"
		if framed {
			name = "complete_tls_frame"
		}
		b.Run(name, func(b *testing.B) {
			s, err := openStore(b.TempDir(), true)
			if err != nil {
				b.Fatal(err)
			}
			defer s.db.Close()
			stop := s.startIndexWriter(context.Background())
			defer stop()
			p := newHTTP(s)
			reader := func(data []byte) io.Reader {
				r := bytes.NewReader(data)
				if framed {
					return capturedReader{Reader: r, complete: true}
				}
				return r
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p.process(reader(request), "benchmark", "client", "tls-hook", 0, false)
				p.process(reader(response), "benchmark", "client", "tls-hook", 0, false)
			}
			b.StopTimer()
			if err := stop(); err != nil {
				b.Fatal(err)
			}
			if s.stats.Transactions != uint64(b.N) || s.fatal != nil {
				b.Fatal("benchmark failed to save request/response pairs", s.stats.Transactions, s.fatal)
			}
			var paired int
			if err := s.db.QueryRow("SELECT COUNT(*) FROM requests WHERE json_extract(data, '$.status')=200").Scan(&paired); err != nil || paired != b.N {
				b.Fatal("benchmark responses were not paired", paired, err)
			}
		})
	}
}
