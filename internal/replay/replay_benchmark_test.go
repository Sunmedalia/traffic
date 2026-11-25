package replay

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// writeBenchmarkPCAP writes connections request/response pairs over IPv4/TCP
// to port 80, one connection per client port, in a session directory.
func writeBenchmarkPCAP(tb testing.TB, connections int, body int) string {
	tb.Helper()
	dir := tb.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"capture_mode":"raw","capture_ports":[80]}`), 0600); err != nil {
		tb.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "packets-source-000001.pcap"))
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		tb.Fatal(err)
	}
	client, server := net.ParseIP("192.0.2.4").To4(), net.ParseIP("192.0.2.5").To4()
	at := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	buf := gopacket.NewSerializeBuffer()
	write := func(port layers.TCPPort, fromServer bool, seq uint32, syn bool, payload []byte) {
		src, dst, sport, dport := client, server, port, layers.TCPPort(80)
		if fromServer {
			src, dst, sport, dport = server, client, 80, port
		}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		tcp := &layers.TCP{SrcPort: sport, DstPort: dport, Seq: seq, SYN: syn, ACK: fromServer || !syn, Window: 65535}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			tb.Fatal(err)
		}
		data := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(data), Length: len(data)}, data); err != nil {
			tb.Fatal(err)
		}
		at = at.Add(time.Microsecond)
	}
	payload := bytes.Repeat([]byte("x"), body)
	for i := 0; i < connections; i++ {
		port := layers.TCPPort(10000 + i)
		request := []byte(fmt.Sprintf("POST /item/%d HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s", i, body, payload))
		response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", body, payload))
		write(port, false, 100, true, nil)
		write(port, true, 500, true, nil)
		write(port, false, 101, false, request)
		write(port, true, 501, false, response)
		// An ACK-only packet exercises the decode path without payload.
		write(port, false, 101+uint32(len(request)), false, nil)
	}
	return dir
}

// BenchmarkReplayPCAP measures offline reconstruction end to end: PCAP read,
// layer decoding, TCP reassembly, HTTP/1.1 parsing, pairing and SQLite writes.
func BenchmarkReplayPCAP(b *testing.B) {
	const connections = 500
	dir := writeBenchmarkPCAP(b, connections, 512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		db, err := sql.Open(index.Driver, ":memory:")
		if err != nil {
			b.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		b.StartTimer()
		stats, err := Build(context.Background(), dir, db, Options{RequestLimit: 1 << 20, ResponseLimit: 1 << 20})
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		var paired int
		if err := db.QueryRow("SELECT COUNT(*) FROM requests WHERE json_extract(data, '$.status')=200").Scan(&paired); err != nil || paired != connections || stats.Transactions != connections {
			b.Fatal("replay lost pairs", paired, stats.Transactions, err)
		}
		db.Close()
		b.StartTimer()
	}
	b.ReportMetric(float64(connections*5*b.N)/b.Elapsed().Seconds(), "packets/s")
}

// BenchmarkHTTPPairingParallel pairs requests and responses on independent
// connections from many goroutines, as concurrent packet directions do.
func BenchmarkHTTPPairingParallel(b *testing.B) {
	body := strings.Repeat("x", 1024)
	request := fmt.Sprintf("POST /benchmark HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	s, err := openStore(b.TempDir(), true)
	if err != nil {
		b.Fatal(err)
	}
	defer s.db.Close()
	stop := s.startIndexWriter(context.Background())
	defer stop()
	p := newHTTP(s)
	var workers atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		key := fmt.Sprintf("parallel-%d", workers.Add(1))
		for pb.Next() {
			p.process(strings.NewReader(request), key, "client", "test", 0, false)
			p.process(strings.NewReader(response), key, "client", "test", 0, false)
		}
	})
	b.StopTimer()
	if err := stop(); err != nil {
		b.Fatal(err)
	}
	if s.stats.Transactions != uint64(b.N) || s.fatal != nil {
		b.Fatal("parallel pairs not saved", s.stats.Transactions, b.N, s.fatal)
	}
}
