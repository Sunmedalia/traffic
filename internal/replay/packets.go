package replay

import (
	"context"
	"fmt"
	"github.com/Sunmedalia/traffic/internal/packetio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type discardStream struct{}

func (discardStream) Reassembled([]tcpassembly.Reassembly) {}
func (discardStream) ReassemblyComplete()                  {}

type streamGeneration struct {
	abort      atomic.Bool
	directions map[string]bool
	id         uint64
}
type streamFactory struct {
	generations map[string]*streamGeneration
	p           *HTTPProcessor
	source      string
}

func (f *streamFactory) New(n, t gopacket.Flow) tcpassembly.Stream {
	r := queuedStream{chunks: make(chan streamChunk, 256), store: f.p.s}
	ends := []string{net.JoinHostPort(n.Src().String(), t.Src().String()), net.JoinHostPort(n.Dst().String(), t.Dst().String())}
	client := ends[0]
	r.server = ends[1]
	direction := ends[0]
	sort.Strings(ends)
	base := strings.Join(ends, "|")
	if f.generations == nil {
		f.generations = map[string]*streamGeneration{}
	}
	g := f.generations[base]
	if g == nil || g.directions[direction] {
		if len(f.generations) > 4000 {
			f.generations = map[string]*streamGeneration{}
		}
		g = &streamGeneration{directions: map[string]bool{}, id: serial.Add(1)}
		f.generations[base] = g
	}
	g.directions[direction] = true
	key := fmt.Sprintf("%s/%s/%d", f.source, base, g.id)
	r.connection = key
	r.abort = &g.abort
	r.processor = f.p
	select {
	case f.p.slots <- struct{}{}:
	default:
		f.p.s.gap("pcap", key, "stream_limit", "directions", 1)
		f.p.s.mu.Lock()
		f.p.s.stats.QueueDropped++
		f.p.s.mu.Unlock()
		return discardStream{}
	}
	f.p.wg.Add(1)
	go func() {
		defer f.p.wg.Done()
		defer func() { <-f.p.slots }()
		defer func() { io.Copy(io.Discard, &r) }()
		f.p.process(&r, key, client, f.source, 0, false)
	}()
	return &r
}

func replayPacketFiles(ctx context.Context, s *Store, p *HTTPProcessor, paths []string, source string) error {
	factory := &streamFactory{p: p, source: source}
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	assembler.MaxBufferedPagesTotal = 4096
	assembler.MaxBufferedPagesPerConnection = 64
	defer assembler.FlushAll()
	var last time.Time
	var packets uint64
	var firstPacketAt, lastPacketAt time.Time
	syncPacketTimestamps := func() {
		if packets == 0 {
			return
		}
		s.mu.Lock()
		s.stats.Packets += packets
		if !firstPacketAt.IsZero() && (s.stats.FirstPacketAt.IsZero() || firstPacketAt.Before(s.stats.FirstPacketAt)) {
			s.stats.FirstPacketAt = firstPacketAt
		}
		if !lastPacketAt.IsZero() && lastPacketAt.After(s.stats.LastPacketAt) {
			s.stats.LastPacketAt = lastPacketAt
		}
		s.mu.Unlock()
	}
	defer syncPacketTimestamps()
	for index, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		reader, err := packetio.NewReader(file)
		if err != nil {
			file.Close()
			return fmt.Errorf("%s: %w", path, err)
		}
		interfaceIndex := -1
		for {
			if err := ctx.Err(); err != nil {
				file.Close()
				return err
			}
			data, ci, err := reader.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err == io.ErrUnexpectedEOF && index == len(paths)-1 {
				s.gap("pcap", source, "truncated_raw_tail", "records", 1)
				break
			}
			if err != nil {
				file.Close()
				return fmt.Errorf("%s: %w", path, err)
			}
			if interfaceIndex == -1 {
				interfaceIndex = ci.InterfaceIndex
			} else if ci.InterfaceIndex != interfaceIndex {
				file.Close()
				return fmt.Errorf("%s: import multi-interface PCAPNG before replay", path)
			}
			packets++
			if !ci.Timestamp.IsZero() {
				ts := ci.Timestamp.UTC()
				if firstPacketAt.IsZero() || ts.Before(firstPacketAt) {
					firstPacketAt = ts
				}
				if ts.After(lastPacketAt) {
					lastPacketAt = ts
				}
			}
			packet := packetio.Decode(data, reader.Link)
			if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && packet.NetworkLayer() != nil && (len(capturePorts) == 0 || capturePorts[int(tcp.SrcPort)] || capturePorts[int(tcp.DstPort)]) {
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, ci.Timestamp)
			}
			if last.IsZero() || ci.Timestamp.Sub(last) > time.Second {
				assembler.FlushOlderThan(ci.Timestamp.Add(-60 * time.Second))
				last = ci.Timestamp
			}
		}
		file.Close()
	}
	return nil
}
