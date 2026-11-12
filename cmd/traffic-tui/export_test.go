package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestExport(t *testing.T) {
	s := tuiTestStore(t)
	if err := os.WriteFile(filepath.Join(s.dir, "capture.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "event.zip")
	transaction := Transaction{ID: "example", Time: time.Now(), Request: []byte("example")}
	raw, err := json.Marshal(transaction)
	if err != nil {
		t.Fatal(err)
	}
	if err = exportEvidence(s, transaction, raw, out); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(out); err != nil {
		t.Fatal(err)
	}
	if err = exportEvidence(s, transaction, raw, out); err == nil {
		t.Fatal("overwrote export")
	}
}

func evidencePacket(t *testing.T, ipv6 bool, port layers.TCPPort) []byte {
	t.Helper()
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{5, 4, 3, 2, 1, 0}, EthernetType: layers.EthernetTypeIPv4}
	tcp := &layers.TCP{SrcPort: port, DstPort: 80, ACK: true}
	var network gopacket.SerializableLayer
	if ipv6 {
		ethernet.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		network = ip
	} else {
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		network = ip
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, network, tcp, gopacket.Payload("evidence")); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
func TestEvidenceEndpointMatching(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		host := "192.0.2.1"
		peer := "192.0.2.2"
		if ipv6 {
			host = "2001:db8::1"
			peer = "2001:db8::2"
		}
		data := evidencePacket(t, ipv6, 12345)
		if !matchesEndpoint(data, layers.LinkTypeEthernet, host, "12345") {
			t.Fatalf("source not matched ipv6=%t", ipv6)
		}
		if !matchesEndpoint(data, layers.LinkTypeEthernet, peer, "80") {
			t.Fatalf("destination not matched ipv6=%t", ipv6)
		}
		for _, endpoint := range [][2]string{{host, "9999"}, {"192.0.2.99", "12345"}, {host, "invalid"}, {"invalid", "12345"}} {
			if matchesEndpoint(data, layers.LinkTypeEthernet, endpoint[0], endpoint[1]) {
				t.Fatalf("unexpected match %v", endpoint)
			}
		}
		if matchesEndpoint(nil, layers.LinkTypeEthernet, host, "12345") {
			t.Fatal("malformed packet matched")
		}
	}
}
func TestExportPacketScopeAndHashes(t *testing.T) {
	for _, folder := range []string{"legacy", "organized"} {
		t.Run(folder, func(t *testing.T) {
			s := tuiTestStore(t)
			if err := os.WriteFile(filepath.Join(s.dir, "capture.lock"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			entry := "packets-test.pcap"
			if folder == "organized" {
				if err := os.MkdirAll(filepath.Join(s.dir, "packets"), 0700); err != nil {
					t.Fatal(err)
				}
				entry = "packets/any-01.pcap"
			}
			packets, err := os.Create(filepath.Join(s.dir, filepath.FromSlash(entry)))
			if err != nil {
				t.Fatal(err)
			}
			writer := pcapgo.NewWriter(packets)
			if err = writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			samples := []struct {
				port  layers.TCPPort
				stamp time.Time
			}{{12345, now}, {9999, now}, {12345, now.Add(-61 * time.Second)}, {12345, now.Add(61 * time.Second)}}
			for _, sample := range samples {
				data := evidencePacket(t, false, sample.port)
				if err = writer.WritePacket(gopacket.CaptureInfo{Timestamp: sample.stamp, CaptureLength: len(data), Length: len(data)}, data); err != nil {
					t.Fatal(err)
				}
			}
			if err = packets.Close(); err != nil {
				t.Fatal(err)
			}
			transaction := Transaction{ID: "packet-scope", Time: now, Client: "192.0.2.1:12345"}
			raw, err := json.Marshal(transaction)
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "evidence.zip")
			if err = exportEvidence(s, transaction, raw, out); err != nil {
				t.Fatal(err)
			}
			archive, err := zip.OpenReader(out)
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			contents := map[string][]byte{}
			for _, fileEntry := range archive.File {
				stream, err := fileEntry.Open()
				if err != nil {
					t.Fatal(err)
				}
				contents[fileEntry.Name], err = io.ReadAll(stream)
				stream.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			var hashes map[string]string
			if err = json.Unmarshal(contents["sha256.json"], &hashes); err != nil {
				t.Fatal(err)
			}
			for name, digest := range hashes {
				sum := sha256.Sum256(contents[name])
				if hex.EncodeToString(sum[:]) != digest {
					t.Fatalf("hash mismatch %s", name)
				}
			}
			reader, err := pcapgo.NewReader(bytes.NewReader(contents[entry]))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = reader.ReadPacketData(); err != nil {
				t.Fatal(err)
			}
			if _, _, err = reader.ReadPacketData(); err != io.EOF {
				t.Fatalf("unexpected extra packet: %v", err)
			}
			lock, err := os.OpenFile(filepath.Join(s.dir, "capture.lock"), os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			blocked := filepath.Join(t.TempDir(), "blocked.zip")
			if err = exportEvidence(s, transaction, raw, blocked); err == nil {
				t.Fatal("export permitted during capture")
			}
			if _, err = os.Stat(blocked); !os.IsNotExist(err) {
				t.Fatal("failed export left a partial archive")
			}
		})
	}
}
