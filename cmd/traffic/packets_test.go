package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestOfflineReassemblyOutOfOrderAndRetransmission(t *testing.T) {
	if e := loadRules(""); e != nil {
		t.Fatal(e)
	}
	input := filepath.Join(t.TempDir(), "source.pcap")
	f, e := os.Create(input)
	if e != nil {
		t.Fatal(e)
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	request := []byte("GET /search?q=hello HTTP/1.1\r\nHost: test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	capturedAt := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	write := func(server bool, seq uint32, syn bool, payload []byte) {
		a, b := net.ParseIP("192.0.2.4"), net.ParseIP("192.0.2.5")
		src, dst := layers.TCPPort(40000), layers.TCPPort(80)
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
		w.WritePacket(gopacket.CaptureInfo{Timestamp: capturedAt, CaptureLength: len(bts), Length: len(bts)}, bts)
	}
	write(false, 100, true, nil)
	write(true, 200, true, nil)
	write(false, 111, false, request[10:])
	write(false, 101, false, request[:10])
	write(false, 101, false, request[:10])
	write(true, 201, false, response)
	f.Close()
	s, e := openStore(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	p := newHTTP(s)
	if e = capturePackets(context.Background(), s, p, "offline", "tcp port 80", input); e != nil {
		t.Fatal(e)
	}
	p.wg.Wait()
	if _, err := os.Stat(filepath.Join(s.dir, "packets", "offline-01.pcap")); err != nil {
		t.Fatalf("packet evidence not organized: %v", err)
	}
	var bts []byte
	if e = s.db.QueryRow("SELECT data FROM requests").Scan(&bts); e != nil {
		t.Fatal(e)
	}
	var result Transaction
	json.Unmarshal(bts, &result)
	if result.Status != 200 || result.URL != "/search?q=hello" || result.Client != "192.0.2.4:40000" {
		t.Fatalf("bad reconstruction %+v", result)
	}
	if !result.Time.Equal(capturedAt) {
		t.Fatalf("offline timestamp %s, want %s", result.Time, capturedAt)
	}
	var count int
	s.db.QueryRow("SELECT count(*) FROM requests").Scan(&count)
	if count != 1 {
		t.Fatalf("duplicate request count %d", count)
	}
}
