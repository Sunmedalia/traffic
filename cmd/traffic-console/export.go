package main

import (
	"archive/zip"
	"bytes"
	"context"
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
	return exportEvidenceContext(context.Background(), s, t, b, path)
}

type preparedEvidence struct {
	store           *Store
	ownedStore      *Store
	lock            *os.File
	t               Transaction
	raw             []byte
	analysisMeta    []byte
	originalEvent   []byte
	originalName    string
	statusData      []byte
	hasStatus       bool
	remote, local   netip.AddrPort
	hasEndpoints    bool
	first, last     time.Time
	packetSource    string
	hasPacketSource bool
	packetFiles     []string
	note            map[string]any
}

func (p *preparedEvidence) close() {
	if p.lock != nil {
		session.UnlockFile(p.lock)
		p.lock.Close()
		p.lock = nil
	}
	if p.ownedStore != nil {
		p.ownedStore.db.Close()
		p.ownedStore = nil
	}
}

func prepareEvidence(ctx context.Context, s *Store, t Transaction, b []byte) (*preparedEvidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := &preparedEvidence{store: s, t: t, raw: b}
	ok := false
	defer func() {
		if !ok {
			p.close()
		}
	}()

	if analysisExists(s.dir) {
		fresh, err := openStore(s.dir)
		if err != nil {
			return nil, err
		}
		p.ownedStore = fresh
		p.store = fresh
		if err = fresh.db.QueryRowContext(ctx, "SELECT data FROM records WHERE id=?", t.ID).Scan(&p.raw); err != nil {
			return nil, err
		}
		p.t = Transaction{}
		if err = json.Unmarshal(p.raw, &p.t); err != nil {
			return nil, err
		}
	}

	lock, err := os.Open(filepath.Join(p.store.dir, "capture.lock"))
	if err != nil {
		return nil, err
	}
	if err = session.LockFile(lock, false); err != nil {
		lock.Close()
		return nil, fmt.Errorf("%w: %w", errCaptureRunning, err)
	}
	p.lock = lock

	if p.store.analysis != nil {
		p.analysisMeta, err = json.MarshalIndent(p.store.analysis, "", "  ")
		if err != nil {
			return nil, err
		}
		if err = p.store.db.QueryRowContext(ctx, "SELECT data FROM main.requests WHERE id=?", p.t.ID).Scan(&p.originalEvent); err != nil {
			return nil, err
		}
		p.originalName = "captured-event.json"
		if p.store.analysis.Reconstructed {
			p.originalName = "reconstructed-event.json"
		}
	}

	if status, err := os.ReadFile(filepath.Join(p.store.dir, "status.json")); err == nil {
		p.statusData = status
		p.hasStatus = true
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	peer := p.t.PeerClient
	if peer == "" {
		peer = p.t.Client
	}
	remote, remoteErr := netip.ParseAddrPort(peer)
	local, localErr := netip.ParseAddrPort(p.t.LocalEndpoint)
	p.hasEndpoints = remoteErr == nil && localErr == nil && remote.Port() != 0 && local.Port() != 0
	p.remote, p.local = remote, local
	p.first, p.last = p.t.Time.Add(-time.Minute), p.t.Time.Add(time.Minute)
	p.packetSource, p.hasPacketSource = strings.CutPrefix(p.t.Source, "pcap:")
	packetScope := "TCP connection endpoints within 60 seconds of transaction time; may include other transactions or reused connections with the same endpoints"
	if p.hasEndpoints && p.hasPacketSource && p.t.ResponseTime.After(p.last) {
		p.last = p.t.ResponseTime
		packetScope = "TCP connection endpoints from 60 seconds before transaction time through the observed response; may include other transactions or reused connections with the same endpoints"
	}
	if !p.hasEndpoints {
		packetScope = "packet selection unavailable because the transaction lacks both transport endpoints"
	}
	p.note = map[string]any{
		"schema_version":       1,
		"source":               p.t.Source,
		"protocol":             p.t.Protocol,
		"stream_id":            p.t.StreamID,
		"integrity_reasons":    p.t.IntegrityReasons,
		"incomplete":           p.t.Incomplete,
		"truncated":            p.t.Truncated,
		"capture_coverage":     session.CoverageWarning,
		"packet_scope":         packetScope,
		"tls_plaintext_source": "process hook; network PCAP remains encrypted",
	}
	if p.hasEndpoints {
		p.note["packet_window_start"], p.note["packet_window_end"] = p.first, p.last
		p.packetFiles, err = session.PacketFiles(p.store.dir)
		if err != nil {
			return nil, err
		}
	}
	var reconstructed *Stats
	if p.store.analysis != nil {
		reconstructed = p.store.analysis.Reconstruction
	}
	if warnings := sessionIntegrityWarnings(p.store.dir, reconstructed); len(warnings) > 0 {
		p.note["session_integrity_warnings"] = warnings
	}
	ok = true
	return p, nil
}

func (p *preparedEvidence) writeTo(ctx context.Context, dst io.Writer) error {
	z := &evidenceZip{Writer: zip.NewWriter(dst), modified: time.Now()}
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
	for _, item := range []struct {
		name string
		data []byte
	}{
		{"event.json", p.raw},
		{"request.http", p.t.Request},
		{"response.http", p.t.Response},
	} {
		if err := add(item.name, item.data); err != nil {
			return err
		}
	}
	if p.store.analysis != nil {
		if err := add("analysis.json", p.analysisMeta); err != nil {
			return err
		}
		if err := add(p.originalName, p.originalEvent); err != nil {
			return err
		}
	}
	if p.hasStatus {
		if err := add("capture-status.json", p.statusData); err != nil {
			return err
		}
	}
	var truncatedFiles []string
	// Capture diagnostics describe the whole session; gap entries are limited
	// to this connection / target or an unattributable backend discontinuity.
	if file, err := os.Open(filepath.Join(p.store.dir, "gaps.jsonl")); err == nil {
		var selected bytes.Buffer
		lines := session.NewJSONLines(file, 1<<20)
		for {
			if err := ctx.Err(); err != nil {
				file.Close()
				return err
			}
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
			if gap.Connection == "" || gap.Connection == p.t.Connection || gap.Connection == strings.TrimPrefix(p.t.Connection, "tls:") || (p.t.TargetID != "" && gap.Connection == p.t.TargetID) {
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
	if p.hasEndpoints && len(p.packetFiles) > 0 {
		// Pre-peek the first packet timestamp of candidate segments so segments
		// completely outside [first, last] are skipped without full packet decoding.
		candidates := make([]int, 0, len(p.packetFiles))
		for i, name := range p.packetFiles {
			if p.hasPacketSource && filepath.Base(session.PacketSegmentGroup(name)) != p.packetSource {
				continue
			}
			candidates = append(candidates, i)
		}
		type segStart struct {
			at time.Time
			ok bool
		}
		starts := make([]segStart, len(candidates))
		for ci, idx := range candidates {
			if err := ctx.Err(); err != nil {
				return err
			}
			at, ok := packetSegmentFirstTime(p.packetFiles[idx])
			starts[ci] = segStart{at: at, ok: ok}
		}
		for ci, idx := range candidates {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := p.packetFiles[idx]
			if starts[ci].ok && starts[ci].at.After(p.last) {
				continue
			}
			if ci+1 < len(candidates) {
				nextIdx := candidates[ci+1]
				if session.PacketSegmentGroup(p.packetFiles[nextIdx]) == session.PacketSegmentGroup(name) && starts[ci+1].ok && starts[ci+1].at.Before(p.first) {
					continue
				}
			}
			entry, digest, truncated, err := exportPacketSegment(ctx, z, p.store.dir, name, p.remote, p.local, p.first, p.last, lastPacketSegment(p.packetFiles, idx))
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
		p.note["truncated_source_files"] = truncatedFiles
	}
	info, _ := json.MarshalIndent(p.note, "", "  ")
	if err := add("evidence.json", info); err != nil {
		return err
	}
	h, _ := json.MarshalIndent(hashes, "", "  ")
	if err := add("sha256.json", h); err != nil {
		return err
	}
	return z.Close()
}

func packetSegmentFirstTime(path string) (time.Time, bool) {
	file, err := os.Open(path)
	if err != nil {
		return time.Time{}, false
	}
	defer file.Close()
	reader, err := packetio.NewReader(file)
	if err != nil {
		return time.Time{}, false
	}
	_, ci, err := reader.ReadPacketData()
	if err != nil {
		return time.Time{}, false
	}
	return ci.Timestamp, true
}

func exportEvidenceContext(ctx context.Context, s *Store, t Transaction, b []byte, path string) error {
	prep, err := prepareEvidence(ctx, s, t, b)
	if err != nil {
		return err
	}
	defer prep.close()

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
	if e = prep.writeTo(ctx, f); e != nil {
		return e
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// exportEvidenceStream validates the session and capture lock before calling
// onReady (which writes HTTP headers), then streams the ZIP archive directly
// into dst without staging a temporary file on disk.
func exportEvidenceStream(ctx context.Context, s *Store, t Transaction, b []byte, onReady func(), dst io.Writer) error {
	prep, err := prepareEvidence(ctx, s, t, b)
	if err != nil {
		return err
	}
	defer prep.close()
	if onReady != nil {
		onReady()
	}
	return prep.writeTo(ctx, dst)
}

func lastPacketSegment(files []string, index int) bool {
	return index+1 == len(files) || session.PacketSegmentGroup(files[index]) != session.PacketSegmentGroup(files[index+1])
}

func exportPacketSegment(ctx context.Context, z *evidenceZip, dir, path string, remote, local netip.AddrPort, first, last time.Time, allowTornTail bool) (entry, digest string, truncated bool, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
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
	for packets := 0; ; packets++ {
		if packets&255 == 0 {
			if err = ctx.Err(); err != nil {
				return entry, "", false, err
			}
		}
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

// evidenceZip stamps every member with the export time. zip.Writer.Create
// leaves the modification time zero, which archive tools show as 1980-00-00.
type evidenceZip struct {
	*zip.Writer
	modified time.Time
}

func (z *evidenceZip) Create(name string) (io.Writer, error) {
	return z.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: z.modified})
}
