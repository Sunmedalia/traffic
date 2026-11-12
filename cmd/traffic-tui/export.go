package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func exportEvidence(s *Store, t Transaction, b []byte, path string) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	z := zip.NewWriter(f)
	hashes := map[string]string{}
	add := func(name string, data []byte) error {
		w, e := z.Create(name)
		if e != nil {
			return e
		}
		if _, e = w.Write(data); e != nil {
			return e
		}
		h := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(h[:])
		return nil
	}
	for name, data := range map[string][]byte{"event.json": b, "request.http": t.Request, "response.http": t.Response} {
		if e = add(name, data); e != nil {
			return e
		}
	}
	note := map[string]any{"schema_version": 1, "source": t.Source, "incomplete": t.Incomplete, "truncated": t.Truncated, "packet_scope": "client endpoint and 120-second window; may include other requests on the same connection; original packets may have rotated", "tls_plaintext_source": "process hook; network PCAP remains encrypted"}
	info, _ := json.MarshalIndent(note, "", "  ")
	if e = add("evidence.json", info); e != nil {
		return e
	}
	lock, e := os.Open(filepath.Join(s.dir, "capture.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); e != nil {
		return fmt.Errorf("stop capture before exporting evidence: %w", e)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	host, port, e := net.SplitHostPort(t.Client)
	if e == nil {
		files, err := session.PacketFiles(s.dir)
		if err != nil {
			return err
		}
		for _, name := range files {
			file, e := os.Open(name)
			if e != nil {
				return e
			}
			handle, e := pcapgo.NewReader(file)
			if e != nil {
				file.Close()
				return e
			}
			entry, err := filepath.Rel(s.dir, name)
			if err != nil {
				file.Close()
				return err
			}
			entry = filepath.ToSlash(entry)
			w, e := z.Create(entry)
			if e != nil {
				file.Close()
				return e
			}
			hash := sha256.New()
			writer := pcapgo.NewWriter(io.MultiWriter(w, hash))
			if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
				file.Close()
				return err
			}
			for {
				data, ci, err := handle.ReadPacketData()
				if err != nil {
					if err != io.EOF {
						file.Close()
						return err
					}
					break
				}
				if ci.Timestamp.Before(t.Time.Add(-60*time.Second)) || ci.Timestamp.After(t.Time.Add(60*time.Second)) {
					continue
				}
				if !matchesEndpoint(data, handle.LinkType(), host, port) {
					continue
				}
				if err = writer.WritePacket(ci, data); err != nil {
					file.Close()
					return err
				}
			}
			file.Close()
			hashes[entry] = hex.EncodeToString(hash.Sum(nil))
		}
	}
	h, _ := json.MarshalIndent(hashes, "", "  ")
	if e = add("sha256.json", h); e != nil {
		return e
	}
	if e = z.Close(); e != nil {
		return e
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// Match the previous BPF scope: TCP, either IP endpoint, and either TCP port.
func matchesEndpoint(data []byte, link layers.LinkType, host, port string) bool {
	ip := net.ParseIP(host)
	number, err := strconv.ParseUint(port, 10, 16)
	if ip == nil || err != nil {
		return false
	}
	packet := gopacket.NewPacket(data, link, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	network := packet.NetworkLayer()
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if network == nil || !ok {
		return false
	}
	flow := network.NetworkFlow()
	return (net.IP(flow.Src().Raw()).Equal(ip) || net.IP(flow.Dst().Raw()).Equal(ip)) && (uint64(tcp.SrcPort) == number || uint64(tcp.DstPort) == number)
}
