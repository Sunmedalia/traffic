package replay

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Sunmedalia/traffic/internal/packetio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"golang.org/x/sync/semaphore"
)

type discardStream struct{}

func (discardStream) Reassembled([]tcpassembly.Reassembly) {}
func (discardStream) ReassemblyComplete()                  {}

type packetDirection struct {
	network, transport gopacket.Flow
}

type streamGeneration struct {
	key        string
	abort      atomic.Bool
	directions map[string]bool
	active     int
	workers    atomic.Int32
	retired    atomic.Bool
}

func (g *streamGeneration) retire(p *HTTPProcessor) {
	g.retired.Store(true)
	if g.workers.Load() == 0 {
		p.forgetHTTP1Pairing(g.key)
	}
}

func (g *streamGeneration) workerDone(p *HTTPProcessor) {
	// A closed input can still hold queued data. Keep the loss marker
	// until the generation is unreachable and all parsers have drained.
	if g.workers.Add(-1) == 0 && g.retired.Load() {
		p.forgetHTTP1Pairing(g.key)
	}
}

type streamFactory struct {
	ctx         context.Context
	budget      *semaphore.Weighted
	generations map[string]*streamGeneration
	p           *HTTPProcessor
	source      string
	directions  map[packetDirection]struct{}
	rejected    uint64
}

func (f *streamFactory) assemble(assembler *tcpassembly.Assembler, n gopacket.Flow, tcp *layers.TCP, at time.Time) {
	direction := packetDirection{n, tcp.TransportFlow()}
	if _, known := f.directions[direction]; !known {
		// ACKs and bare FIN/RST cannot open a new assembler direction.
		if !tcp.SYN && len(tcp.Payload) == 0 {
			return
		}
		if len(f.directions) >= cap(f.p.slots) {
			// Reject before tcpassembly allocates a connection, even if
			// thousands of new directions share the same timestamp.
			f.rejected++
			return
		}
	}
	assembler.AssembleWithTimestamp(n, tcp, at)
}

func (f *streamFactory) New(n, t gopacket.Flow) tcpassembly.Stream {
	ends := []string{net.JoinHostPort(n.Src().String(), t.Src().String()), net.JoinHostPort(n.Dst().String(), t.Dst().String())}
	client, server := ends[0], ends[1]
	sort.Strings(ends)
	base := strings.Join(ends, "|")
	if f.generations == nil {
		f.generations = map[string]*streamGeneration{}
	}
	previous := f.generations[base]
	g := previous
	if g == nil || g.directions[client] {
		g = &streamGeneration{
			key:        fmt.Sprintf("%s/%s/%d", f.source, base, serial.Add(1)),
			directions: map[string]bool{},
		}
	}
	// Readers whose input is already closed can finish without new packets.
	select {
	case f.p.slots <- struct{}{}:
	case <-f.ctx.Done():
		return discardStream{}
	}
	if len(f.generations) >= 4000 && previous == nil {
		// Reclaim closed, one-sided generations without disturbing open
		// directions that can still receive their peer's first packet.
		for base, old := range f.generations {
			if old.active == 0 {
				delete(f.generations, base)
				old.retire(f.p)
			}
		}
	}
	f.generations[base] = g
	if previous != nil && previous != g {
		previous.retire(f.p)
	}
	g.directions[client] = true
	g.active++
	g.workers.Add(1)
	if f.directions == nil {
		f.directions = make(map[packetDirection]struct{})
	}
	direction := packetDirection{n, t}
	f.directions[direction] = struct{}{}
	r := queuedStream{
		ctx: f.ctx, budget: f.budget, chunks: make(chan streamChunk, 256),
		store: f.p.s, server: server, connection: g.key, abort: &g.abort, processor: f.p,
		onClose: func() {
			delete(f.directions, direction)
			g.active--
			if g.active == 0 && len(g.directions) == 2 && f.generations[base] == g {
				delete(f.generations, base)
				g.retire(f.p)
			}
		},
	}
	f.p.wg.Add(1)
	go func() {
		defer f.p.wg.Done()
		defer func() { <-f.p.slots }()
		defer g.workerDone(f.p)
		defer func() { io.Copy(io.Discard, &r) }()
		f.p.process(&r, g.key, client, f.source, 0, false)
	}()
	return &r
}

func replayPacketFiles(ctx context.Context, s *Store, p *HTTPProcessor, paths []string, source string) (err error) {
	factory := &streamFactory{ctx: ctx, budget: semaphore.NewWeighted(packetQueueBudget), p: p, source: source}
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	assembler.MaxBufferedPagesTotal = 4096
	assembler.MaxBufferedPagesPerConnection = 64
	defer func() {
		assembler.FlushAll()
		if factory.rejected > 0 {
			s.gap("pcap", source, "stream_limit", "packets", factory.rejected)
			s.mu.Lock()
			s.stats.QueueDropped += factory.rejected
			s.mu.Unlock()
		}
		if err == nil {
			err = ctx.Err()
		}
	}()
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
				factory.assemble(assembler, packet.NetworkLayer().NetworkFlow(), tcp, ci.Timestamp)
			}
			if last.IsZero() || ci.Timestamp.Sub(last) > time.Second {
				cutoff := ci.Timestamp.Add(-time.Minute)
				// Flush expired out-of-order data without closing a
				// contiguous stream just because its peer is idle.
				assembler.FlushWithOptions(tcpassembly.FlushOptions{T: cutoff})
				if len(factory.directions) >= cap(p.slots)*3/4 {
					_, closed := assembler.FlushOlderThan(cutoff)
					if closed > 0 {
						s.gap("pcap", source, "stream_idle_eviction", "directions", uint64(closed))
					}
				}
				last = ci.Timestamp
			}
		}
		file.Close()
	}
	return nil
}
