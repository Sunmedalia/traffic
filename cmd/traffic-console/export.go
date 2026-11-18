package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sunmedalia/traffic/internal/packetio"
	"github.com/Sunmedalia/traffic/internal/session"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var errCaptureRunning = errors.New("stop capture before exporting evidence")

func exportEvidence(s *Store, t Transaction, b []byte, path string) error {
	if analysisExists(s.dir) {
		fresh, err := openStore(s.dir)
		if err != nil {
			return err
		}
		defer fresh.db.Close()
		s = fresh
		if err = s.db.QueryRow("SELECT data FROM requests WHERE id=?", t.ID).Scan(&b); err != nil {
			return err
		}
		t = Transaction{}
		if err = json.Unmarshal(b, &t); err != nil {
			return err
		}
	}

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
	peer := t.PeerClient
	if peer == "" {
		peer = t.Client
	}
	remote, remoteErr := netip.ParseAddrPort(peer)
	local, localErr := netip.ParseAddrPort(t.LocalEndpoint)
	hasEndpoints := remoteErr == nil && localErr == nil && remote.Port() != 0 && local.Port() != 0
	packetScope := "TCP connection endpoints within 60 seconds of transaction time; may include other transactions or reused connections with the same endpoints"
	if !hasEndpoints {
		packetScope = "packet selection unavailable because the transaction lacks both transport endpoints"
	}
	note := map[string]any{"schema_version": 1, "source": t.Source, "protocol": t.Protocol, "stream_id": t.StreamID, "integrity_reasons": t.IntegrityReasons, "incomplete": t.Incomplete, "truncated": t.Truncated, "capture_coverage": session.CoverageWarning, "packet_scope": packetScope, "tls_plaintext_source": "process hook; network PCAP remains encrypted"}
	var truncatedFiles []string
	lock, e := os.Open(filepath.Join(s.dir, "capture.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = session.LockFile(lock, false); e != nil {
		return fmt.Errorf("%w: %w", errCaptureRunning, e)
	}
	defer session.UnlockFile(lock)
	if s.analysis != nil {
		metadata, err := json.MarshalIndent(s.analysis, "", "  ")
		if err != nil {
			return err
		}
		if err = add("analysis.json", metadata); err != nil {
			return err
		}
		var original []byte
		if err = s.db.QueryRow("SELECT data FROM main.requests WHERE id=?", t.ID).Scan(&original); err != nil {
			return err
		}
		name := "captured-event.json"
		if s.analysis.Reconstructed {
			name = "reconstructed-event.json"
		}
		if err = add(name, original); err != nil {
			return err
		}
	}
	// Capture diagnostics describe the whole session; gap entries are limited
	// to this connection / target or an unattributable backend discontinuity.
	if status, err := os.ReadFile(filepath.Join(s.dir, "status.json")); err == nil {
		if err := add("capture-status.json", status); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if file, err := os.Open(filepath.Join(s.dir, "gaps.jsonl")); err == nil {
		var selected bytes.Buffer
		lines := session.NewJSONLines(file, 1<<20)
		for {
			var gap session.GapEvent
			err := lines.Next(&gap)
			if err == io.EOF {
				break
			}
			if err == session.ErrTruncatedJSONLine {
				truncatedFiles = append(truncatedFiles, "gaps.jsonl")
				break
			}
			if err != nil {
				file.Close()
				return err
			}
			if gap.Connection == "" || gap.Connection == t.Connection || gap.Connection == strings.TrimPrefix(t.Connection, "tls:") || (t.TargetID != "" && gap.Connection == t.TargetID) {
				selected.Write(lines.Bytes())
				selected.WriteByte('\n')
			}
		}
		file.Close()
		if err := add("capture-gaps.jsonl", selected.Bytes()); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if hasEndpoints {
		files, err := session.PacketFiles(s.dir)
		if err != nil {
			return err
		}
		first, last := t.Time.Add(-time.Minute), t.Time.Add(time.Minute)
		packetSource, hasPacketSource := strings.CutPrefix(t.Source, "pcap:")
		for i, name := range files {
			if hasPacketSource && filepath.Base(session.PacketSegmentGroup(name)) != packetSource {
				continue
			}
			entry, digest, truncated, err := exportPacketSegment(z, s.dir, name, remote, local, first, last, lastPacketSegment(files, i))
			if err != nil {
				return err
			}
			if truncated {
				truncatedFiles = append(truncatedFiles, filepath.ToSlash(entry))
			}
			if digest != "" {
				hashes[entry] = digest
			}
		}
	}
	if len(truncatedFiles) > 0 {
		note["truncated_source_files"] = truncatedFiles
	}
	info, _ := json.MarshalIndent(note, "", "  ")
	if e = add("evidence.json", info); e != nil {
		return e
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

func lastPacketSegment(files []string, index int) bool {
	return index+1 == len(files) || session.PacketSegmentGroup(files[index]) != session.PacketSegmentGroup(files[index+1])
}

func exportPacketSegment(z *zip.Writer, dir, path string, remote, local netip.AddrPort, first, last time.Time, allowTornTail bool) (entry, digest string, truncated bool, err error) {
	entry, err = filepath.Rel(dir, path)
	if err != nil {
		return
	}
	entry = filepath.ToSlash(entry)
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	reader, err := packetio.NewReader(file)
	if err != nil {
		return
	}
	hash := sha256.New()
	var writer *pcapgo.Writer
	interfaceIndex := -1
	for {
		data, ci, readErr := reader.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		if readErr == io.ErrUnexpectedEOF && allowTornTail {
			truncated = true
			break
		}
		if readErr != nil {
			return entry, "", false, fmt.Errorf("%s: %w", entry, readErr)
		}
		if interfaceIndex == -1 {
			interfaceIndex = ci.InterfaceIndex
		} else if ci.InterfaceIndex != interfaceIndex {
			return entry, "", false, fmt.Errorf("%s: import multi-interface PCAPNG before export", entry)
		}
		if ci.Timestamp.Before(first) || ci.Timestamp.After(last) || !matchesConnection(data, reader.Link, remote, local) {
			continue
		}
		if writer == nil {
			member, err := z.Create(entry)
			if err != nil {
				return entry, "", false, err
			}
			output := io.MultiWriter(member, hash)
			if err := packetio.WriteHeader(output, reader.Snap, reader.Link); err != nil {
				return entry, "", false, err
			}
			writer = pcapgo.NewWriterNanos(output)
		}
		if err := writer.WritePacket(ci, data); err != nil {
			return entry, "", false, err
		}
	}
	if writer != nil {
		digest = hex.EncodeToString(hash.Sum(nil))
	}
	return
}

func matchesConnection(data []byte, link uint32, remote, local netip.AddrPort) bool {
	packet := packetio.Decode(data, link)
	network := packet.NetworkLayer()
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if network == nil || !ok {
		return false
	}
	flow := network.NetworkFlow()
	src, srcOK := netip.AddrFromSlice(flow.Src().Raw())
	dst, dstOK := netip.AddrFromSlice(flow.Dst().Raw())
	if !srcOK || !dstOK {
		return false
	}
	source := netip.AddrPortFrom(src.Unmap(), uint16(tcp.SrcPort))
	destination := netip.AddrPortFrom(dst.Unmap(), uint16(tcp.DstPort))
	remote = netip.AddrPortFrom(remote.Addr().WithZone("").Unmap(), remote.Port())
	local = netip.AddrPortFrom(local.Addr().WithZone("").Unmap(), local.Port())
	return (source == remote && destination == local) || (source == local && destination == remote)
}
