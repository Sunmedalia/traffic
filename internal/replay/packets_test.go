package replay

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sync/semaphore"
)

func writeReplayPCAP(t *testing.T) (string, func(time.Time, layers.TCPPort, bool, uint32, bool, []byte), func()) {
	t.Helper()
	input := filepath.Join(t.TempDir(), "packets-source-000001.pcap")
	f, e := os.Create(input)
	if e != nil {
		t.Fatal(e)
	}
	w := pcapgo.NewWriter(f)
	t.Cleanup(func() { _ = f.Close() })
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	write := func(capturedAt time.Time, port layers.TCPPort, server bool, seq uint32, syn bool, payload []byte) {
		t.Helper()
		a, b := net.ParseIP("192.0.2.4"), net.ParseIP("192.0.2.5")
		src, dst := port, layers.TCPPort(80)
		if server {
			a, b = b, a
			src, dst = dst, src
		}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: a, DstIP: b}
		tcp := &layers.TCP{SrcPort: src, DstPort: dst, Seq: seq, SYN: syn, ACK: server || !syn, Window: 65535}
		tcp.SetNetworkLayerForChecksum(ip)
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
		buf := gopacket.NewSerializeBuffer()
		if e := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); e != nil {
			t.Fatal(e)
		}
		bts := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: capturedAt, CaptureLength: len(bts), Length: len(bts)}, bts); err != nil {
			t.Fatal(err)
		}
	}
	return input, write, func() {
		t.Helper()
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func replayTestPCAP(t *testing.T, input string) ([]Transaction, map[string]uint64) {
	t.Helper()
	dir := filepath.Dir(input)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"capture_mode":"raw","capture_ports":[80]}`), 0600); err != nil {
		t.Fatal(err)
	}
	db, e := sql.Open(index.Driver, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stats, e := Build(ctx, dir, db, Options{RequestLimit: 1 << 20, ResponseLimit: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	rows, e := db.Query("SELECT data FROM requests ORDER BY time,id")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	var records []Transaction
	for rows.Next() {
		var data []byte
		var record Transaction
		if err := rows.Scan(&data); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if e := rows.Err(); e != nil {
		t.Fatal(e)
	}
	return records, stats.GapCounts
}

func TestOfflineReassemblyOutOfOrderAndRetransmission(t *testing.T) {
	input, write, closePCAP := writeReplayPCAP(t)
	request := []byte("GET /search?q=hello HTTP/1.1\r\nHost: test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	capturedAt := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	write(capturedAt, 40000, false, 100, true, nil)
	write(capturedAt, 40000, true, 200, true, nil)
	write(capturedAt, 40000, false, 111, false, request[10:])
	write(capturedAt, 40000, false, 101, false, request[:10])
	write(capturedAt, 40000, false, 101, false, request[:10])
	write(capturedAt, 40000, true, 201, false, response)
	closePCAP()
	records, gaps := replayTestPCAP(t, input)
	if len(records) != 1 || len(gaps) != 0 {
		t.Fatalf("got %d requests and gaps %v", len(records), gaps)
	}
	result := records[0]
	if result.Status != 200 || result.URL != "/search?q=hello" || result.Client != "192.0.2.4:40000" {
		t.Fatalf("bad reconstruction %+v", result)
	}
	if !result.Time.Equal(capturedAt) {
		t.Fatalf("offline timestamp %s, want %s", result.Time, capturedAt)
	}
}

func TestOfflineReassemblyPreservesBurst(t *testing.T) {
	input, write, closePCAP := writeReplayPCAP(t)
	body := bytes.Repeat([]byte("z"), 900000)
	header := []byte(fmt.Sprintf("POST /burst HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n", len(body)))
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	capturedAt := time.Unix(1600000000, 0)
	write(capturedAt, 40000, false, 100, true, nil)
	write(capturedAt, 40000, true, 200, true, nil)
	write(capturedAt, 40000, false, 101, false, header)
	for i := 0; i < len(body); i += 1000 {
		write(capturedAt, 40000, false, uint32(101+len(header)+i), false, body[i:i+1000])
	}
	write(capturedAt, 40000, true, 201, false, response)
	closePCAP()

	for _, cpu := range []int{1, 4} {
		t.Run(fmt.Sprint(cpu), func(t *testing.T) {
			previous := runtime.GOMAXPROCS(cpu)
			defer runtime.GOMAXPROCS(previous)
			records, gaps := replayTestPCAP(t, input)
			if len(records) != 1 || len(gaps) != 0 {
				t.Fatalf("got %d requests and gaps %v", len(records), gaps)
			}
			checkReplayTransaction(t, records[0], "/burst", body)
		})
	}
}

func TestOfflineReassemblyKeepsIdleConnections(t *testing.T) {
	input, write, closePCAP := writeReplayPCAP(t)
	capturedAt := time.Unix(1600000000, 0)
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	request := []byte("GET /slow HTTP/1.1\r\nHost: test\r\n\r\n")
	write(capturedAt, 40000, false, 100, true, nil)
	write(capturedAt, 40000, true, 200, true, nil)
	write(capturedAt, 40000, false, 101, false, request)

	unrelatedAt := capturedAt.Add(61 * time.Second)
	write(unrelatedAt, 40001, false, 300, true, nil)
	write(unrelatedAt, 40001, true, 400, true, nil)
	write(unrelatedAt, 40001, false, 301, false, []byte("GET /other HTTP/1.1\r\nHost: test\r\n\r\n"))
	write(unrelatedAt, 40001, true, 401, false, response)
	write(unrelatedAt.Add(time.Second), 40000, true, 201, false, response)

	reusedAt := capturedAt.Add(125 * time.Second)
	write(reusedAt, 40000, false, 101+uint32(len(request)), false, []byte("GET /reuse HTTP/1.1\r\nHost: test\r\n\r\n"))
	write(reusedAt, 40000, true, 201+uint32(len(response)), false, response)
	closePCAP()
	records, gaps := replayTestPCAP(t, input)
	if len(records) != 3 || len(gaps) != 0 {
		t.Fatalf("got %d requests and gaps %v", len(records), gaps)
	}
	for i, url := range []string{"/slow", "/other", "/reuse"} {
		checkReplayTransaction(t, records[i], url, nil)
	}
	if want := unrelatedAt.Add(time.Second); !records[0].ResponseTime.Equal(want) {
		t.Fatalf("slow response packet timestamp = %s, want %s", records[0].ResponseTime, want)
	}
}

func TestOfflineReassemblyReportsMissingSequence(t *testing.T) {
	input, write, closePCAP := writeReplayPCAP(t)
	capturedAt := time.Unix(1600000000, 0)
	write(capturedAt, 40000, false, 100, true, nil)
	write(capturedAt, 40000, true, 200, true, nil)
	write(capturedAt, 40000, false, 101, false, []byte("GET /gap HTTP/1.1\r\nHost: test\r\n\r\n"))
	write(capturedAt, 40000, true, 211, false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	closePCAP()
	records, gaps := replayTestPCAP(t, input)
	if gaps["pcap/tcp_sequence_gap/events"] != 1 {
		t.Fatalf("missing TCP sequence gap: %v", gaps)
	}
	for _, record := range records {
		if record.Status != 0 || !record.Incomplete {
			t.Fatal("paired a response across a TCP sequence gap")
		}
	}
}

func TestOfflineReassemblyReusesClosedStreamSlots(t *testing.T) {
	s := &Store{}
	p := newHTTP(s)
	p.slots = make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	factory := &streamFactory{ctx: ctx, budget: semaphore.NewWeighted(packetQueueBudget), p: p, source: "pcap:test"}
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	transport := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x9c, 0x40}, []byte{0, 80})
	for range 20 {
		stream := factory.New(network, transport)
		stream.ReassemblyComplete()
		if _, ok := stream.(*queuedStream); !ok {
			t.Fatal("discarded a stream while a finished parser released its slot")
		}
	}
	p.wg.Wait()
	if len(p.slots) != 0 || len(factory.directions) != 0 || len(s.stats.GapCounts) != 0 {
		t.Fatalf("streams did not drain cleanly: %v", s.stats.GapCounts)
	}
}

func TestOfflineReassemblyReleasesPairingLossAfterBothDirectionsDrain(t *testing.T) {
	s := &Store{}
	p := newHTTP(s)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	f := &streamFactory{ctx: ctx, budget: semaphore.NewWeighted(packetQueueBudget), p: p, source: "pcap:test"}
	n := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	port := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x9c, 0x40}, []byte{0, 80})
	for range 8193 {
		req := f.New(n, port).(*queuedStream)
		p.mu.Lock()
		p.loseHTTP1PairingLocked(req.connection, "pipeline_limit")
		p.mu.Unlock()
		req.ReassemblyComplete()
		p.wg.Wait()
		// A peer can appear after the first direction has drained. It
		// still belongs to the original generation and must not pair.
		resp := f.New(n.Reverse(), port.Reverse()).(*queuedStream)
		p.mu.Lock()
		reason := p.http1PairingLossLocked(resp.connection)
		p.mu.Unlock()
		resp.ReassemblyComplete()
		p.wg.Wait()
		if resp.connection != req.connection || reason != "pipeline_limit" {
			t.Fatalf("late peer lost generation or guard: key=%s request=%s reason=%q", resp.connection, req.connection, reason)
		}
	}
	if len(p.pairingLost) != 0 || p.pairingStopped {
		t.Fatalf("drained generations left %d loss markers and stopped pairing=%t", len(p.pairingLost), p.pairingStopped)
	}
}

func TestOfflineReassemblyRetiresReplacedOneSidedGeneration(t *testing.T) {
	p := newHTTP(&Store{})
	f := &streamFactory{ctx: t.Context(), budget: semaphore.NewWeighted(packetQueueBudget), p: p, source: "pcap:test"}
	n := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	port := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x9c, 0x40}, []byte{0, 80})
	first := f.New(n, port).(*queuedStream)
	p.mu.Lock()
	p.loseHTTP1PairingLocked(first.connection, "pipeline_limit")
	p.mu.Unlock()
	first.ReassemblyComplete()
	p.wg.Wait()
	replacement := f.New(n, port).(*queuedStream)
	replacement.ReassemblyComplete()
	p.wg.Wait()
	if replacement.connection == first.connection || len(p.pairingLost) != 0 {
		t.Fatal("replacing the one-sided generation did not retire its pairing guard")
	}
}

func TestOfflineReassemblyBoundsAssemblerDirections(t *testing.T) {
	s := &Store{}
	p := newHTTP(s)
	p.slots = make(chan struct{}, 2)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	f := &streamFactory{ctx: ctx, budget: semaphore.NewWeighted(packetQueueBudget), p: p, source: "pcap:test"}
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(f))
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	at := time.Unix(1600000000, 0)
	send := func(port layers.TCPPort, syn bool) {
		tcp := &layers.TCP{SrcPort: port, DstPort: 80, Seq: 100, SYN: syn, FIN: !syn}
		if !syn {
			tcp.Seq++
		}
		tcp.SetInternalPortsForTesting()
		f.assemble(assembler, network, tcp, at)
	}
	for port := layers.TCPPort(40000); port < 40020; port++ {
		send(port, true)
	}
	send(40000, false)
	send(40002, true)
	closed := assembler.FlushAll()
	p.wg.Wait()
	if closed != 2 || len(f.directions) != 0 || f.rejected != 18 {
		t.Fatalf("retained at EOF=%d remaining=%d rejected=%d", closed, len(f.directions), f.rejected)
	}
}

func TestOfflineHTTP2UsesPerStreamTimestamps(t *testing.T) {
	input, write, closePCAP := writeReplayPCAP(t)
	at := time.Unix(1600000000, 0)
	var client, server, block bytes.Buffer
	client.WriteString(h2Preface)
	request, response := http2.NewFramer(&client, nil), http2.NewFramer(&server, nil)
	if err := request.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := response.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	reqEncoder, respEncoder := hpack.NewEncoder(&block), hpack.NewEncoder(&block)
	write(at, 40000, false, 100, true, nil)
	write(at, 40000, true, 200, true, nil)
	cseq, sseq := uint32(101), uint32(201)
	for i, url := range []string{"/one", "/three"} {
		stamp := at.Add(time.Duration(i) * 20 * time.Second)
		id := uint32(2*i + 1)
		h2Headers(t, reqEncoder, &block, request, id, true, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: url})
		h2Headers(t, respEncoder, &block, response, id, true, hpack.HeaderField{Name: ":status", Value: "200"})
		write(stamp, 40000, false, cseq, false, client.Bytes())
		write(stamp.Add(time.Second), 40000, true, sseq, false, server.Bytes())
		cseq, sseq = cseq+uint32(client.Len()), sseq+uint32(server.Len())
		client.Reset()
		server.Reset()
	}
	closePCAP()
	records, gaps := replayTestPCAP(t, input)
	if len(records) != 2 || len(gaps) != 0 {
		t.Fatalf("got %d records and gaps %v", len(records), gaps)
	}
	for i, url := range []string{"/one", "/three"} {
		want := at.Add(time.Duration(i) * 20 * time.Second)
		r := records[i]
		if r.URL != url || r.Status != 200 || r.Incomplete || !r.Time.Equal(want) || !r.ResponseTime.Equal(want.Add(time.Second)) {
			t.Fatalf("%s: status=%d incomplete=%t timestamps=%s/%s, want request %s", r.URL, r.Status, r.Incomplete, r.Time, r.ResponseTime, want)
		}
	}
}

func checkReplayTransaction(t *testing.T, record Transaction, url string, body []byte) {
	t.Helper()
	_, requestBody, _ := bytes.Cut(record.Request, []byte("\r\n\r\n"))
	_, responseBody, _ := bytes.Cut(record.Response, []byte("\r\n\r\n"))
	if record.URL != url || record.Status != 200 || record.Incomplete || record.Truncated ||
		!bytes.Equal(requestBody, body) || string(responseBody) != "ok" {
		t.Fatalf("got %s status %d incomplete=%t truncated=%t body sizes %d/%d, want %s with body sizes %d/2",
			record.URL, record.Status, record.Incomplete, record.Truncated, len(requestBody), len(responseBody), url, len(body))
	}
}
