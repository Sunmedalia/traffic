package replay

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
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

// packetDirectionLimit bounds TCP assembler state. Directions that never carry
// payload, such as unanswered SYNs, hold no parser and cost a few hundred bytes,
// so a burst of them must not crowd out connections that carry requests.
const packetDirectionLimit = 1 << 16

type streamFactory struct {
	ctx           context.Context
	budget        *semaphore.Weighted
	generations   map[string]*streamGeneration
	p             *HTTPProcessor
	source        string
	directions    map[packetDirection]*queuedStream
	parsing       map[*queuedStream]struct{}
	maxDirections int
	// reserved is a parser slot taken for the packet being assembled; the
	// direction it opens or continues consumes it on its first payload.
	reserved bool
	// closedParsers counts started directions whose input has closed. Their
	// parsers release a slot once they drain the queued input.
	closedParsers  uint64
	reclaimAt      int
	directionSweep time.Time
	rejected       uint64
}

func (f *streamFactory) directionLimit() int {
	if f.maxDirections > 0 {
		return f.maxDirections
	}
	return packetDirectionLimit
}

func (f *streamFactory) assemble(assembler *tcpassembly.Assembler, n gopacket.Flow, tcp *layers.TCP, at time.Time) {
	direction := packetDirection{n, tcp.TransportFlow()}
	stream, known := f.directions[direction]
	if !known {
		// ACKs and bare FIN/RST cannot open a new assembler direction.
		if !tcp.SYN && len(tcp.Payload) == 0 {
			return
		}
		if len(f.directions) >= f.directionLimit() && at.Sub(f.directionSweep) >= time.Second {
			// Directions idle for a second, mostly unanswered SYNs, make
			// room. One sweep per second keeps a flood from rescanning
			// the whole table for every packet.
			f.directionSweep = at
			f.evictIdle(assembler, at.Add(-time.Second))
		}
		if len(f.directions) >= f.directionLimit() {
			// Reject before tcpassembly allocates a connection, even if
			// thousands of new directions share the same timestamp.
			f.rejected++
			return
		}
	}
	if len(tcp.Payload) > 0 && (stream == nil || !stream.started) {
		if !f.reserveParser(assembler) {
			f.rejected++
			return
		}
		defer f.releaseReservation()
	}
	assembler.AssembleWithTimestamp(n, tcp, at)
	if stream := f.directions[direction]; stream != nil {
		// tcpassembly ages each direction by the last packet it was given.
		stream.lastSeen = at
	}
}

// reserveParser takes a parser slot before payload reaches a direction that
// has none. A parser draining closed input frees its slot soon, so the reader
// waits for it, as it waits for parsers to consume queued payload. Only when
// open directions hold every slot are the least recently active of them
// closed, an eighth at a time.
func (f *streamFactory) reserveParser(assembler *tcpassembly.Assembler) bool {
	if f.reserved {
		return true
	}
	for {
		select {
		case f.p.slots <- struct{}{}:
			f.reserved = true
			return true
		default:
		}
		if len(f.p.slots) > len(f.parsing) {
			select {
			case f.p.slots <- struct{}{}:
				f.reserved = true
				return true
			case <-f.ctx.Done():
				return false
			}
		}
		cutoff, ok := f.evictionCutoff()
		if !ok {
			return false
		}
		before := f.closedParsers
		f.evictIdle(assembler, cutoff)
		if f.closedParsers == before {
			return false
		}
	}
}

// evictionCutoff closes the least recently active eighth of the parsed
// directions, so one assembler sweep serves many new connections.
func (f *streamFactory) evictionCutoff() (time.Time, bool) {
	seen := make([]time.Time, 0, len(f.parsing))
	for stream := range f.parsing {
		seen = append(seen, stream.lastSeen)
	}
	if len(seen) == 0 {
		return time.Time{}, false
	}
	slices.SortFunc(seen, time.Time.Compare)
	return seen[max(1, len(seen)/8)-1].Add(time.Nanosecond), true
}

func (f *streamFactory) releaseReservation() {
	if f.reserved {
		f.reserved = false
		<-f.p.slots
	}
}

// takeParser hands the reserved slot to a direction's first payload. Payload
// released later by a flush has no reservation and uses a free slot only.
func (f *streamFactory) takeParser() bool {
	if f.reserved {
		f.reserved = false
		return true
	}
	select {
	case f.p.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (f *streamFactory) evictIdle(assembler *tcpassembly.Assembler, cutoff time.Time) {
	if _, closed := assembler.FlushOlderThan(cutoff); closed > 0 {
		f.p.s.gap("pcap", f.source, "stream_idle_eviction", "directions", uint64(closed))
	}
}

func (f *streamFactory) New(n, t gopacket.Flow) tcpassembly.Stream {
	if f.ctx.Err() != nil {
		return discardStream{}
	}
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
	if previous == nil && len(f.generations) >= max(4000, f.reclaimAt) {
		// Reclaim closed, one-sided generations without disturbing open
		// directions that can still receive their peer's first packet. The
		// next sweep waits until the map doubles, so many open directions
		// do not make every new connection scan all of them.
		for base, old := range f.generations {
			if old.active == 0 {
				delete(f.generations, base)
				old.retire(f.p)
			}
		}
		f.reclaimAt = 2 * len(f.generations)
	}
	f.generations[base] = g
	if previous != nil && previous != g {
		previous.retire(f.p)
	}
	g.directions[client] = true
	g.active++
	if f.directions == nil {
		f.directions = make(map[packetDirection]*queuedStream)
	}
	direction := packetDirection{n, t}
	r := &queuedStream{
		ctx: f.ctx, budget: f.budget, factory: f,
		store: f.p.s, server: server, connection: g.key, abort: &g.abort, processor: f.p,
	}
	r.onClose = func() {
		delete(f.directions, direction)
		if r.started {
			delete(f.parsing, r)
			f.closedParsers++
		}
		g.active--
		if g.active == 0 && len(g.directions) == 2 && f.generations[base] == g {
			delete(f.generations, base)
			g.retire(f.p)
		}
	}
	// The parser starts with the first payload: a direction that carries no
	// data, such as an unanswered SYN, holds neither a goroutine nor a slot.
	r.launch = func() {
		if f.parsing == nil {
			f.parsing = make(map[*queuedStream]struct{})
		}
		f.parsing[r] = struct{}{}
		g.workers.Add(1)
		f.p.wg.Add(1)
		go func() {
			defer f.p.wg.Done()
			defer func() { <-f.p.slots }()
			defer g.workerDone(f.p)
			defer func() { io.Copy(io.Discard, r) }()
			f.p.process(r, g.key, client, f.source, 0, false)
		}()
	}
	f.directions[direction] = r
	return r
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
				if len(factory.directions) >= factory.directionLimit()*3/4 || len(p.slots) >= cap(p.slots)*3/4 {
					factory.evictIdle(assembler, cutoff)
				}
				last = ci.Timestamp
			}
		}
		file.Close()
	}
	return nil
}
