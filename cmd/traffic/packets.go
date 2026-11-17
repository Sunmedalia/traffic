package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
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
	r := queuedStream{chunks: make(chan []byte, 256), store: f.p.s}
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

type packetRing struct {
	dir, iface string
	file       *os.File
	buffer     *bufio.Writer
	writer     *pcapgo.Writer
	size       int64
	index      int
	link       layers.LinkType
	snaplen    uint32
}

func (r *packetRing) write(ci gopacket.CaptureInfo, b []byte) error {
	if r.file == nil || r.size+int64(len(b))+16 > 64<<20 {
		if r.file != nil {
			if err := r.close(); err != nil {
				return err
			}
		}
		r.index = (r.index + 1) % 16
		name := filepath.Join(r.dir, fmt.Sprintf("%s-%02d.pcap", packetInterfaceName(r.iface), r.index))
		f, e := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		r.file = f
		r.buffer = bufio.NewWriterSize(f, 256<<10)
		r.writer = pcapgo.NewWriter(r.buffer)
		if e = r.writer.WriteFileHeader(r.snaplen, r.link); e != nil {
			return e
		}
		r.size = 24
	}
	e := r.writer.WritePacket(ci, b)
	r.size += int64(len(b)) + 16
	return e
}

func (r *packetRing) close() error {
	if r.file == nil {
		return nil
	}
	err := r.buffer.Flush()
	err = errors.Join(err, r.file.Sync(), r.file.Close())
	r.file, r.buffer, r.writer = nil, nil, nil
	return err
}
func capturePackets(ctx context.Context, s *Store, p *HTTPProcessor, iface, filter, input string) error {
	var h packetHandle
	var e error
	if input != "" {
		h, e = openOfflinePacket(input)
	} else {
		h, e = openLivePacket(ctx, iface)
	}
	if e != nil {
		return e
	}
	defer h.Close()
	if input == "" {
		defer func() {
			if stats, err := h.Stats(); err == nil {
				s.recordPacketDrops(iface, uint64(stats.PacketsDropped+stats.PacketsIfDropped))
			}
		}()
	}
	if e = h.SetBPFFilter(filter); e != nil {
		return e
	}
	factory := &streamFactory{p: p, source: "pcap:" + iface}
	a := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	a.MaxBufferedPagesTotal = 4096
	a.MaxBufferedPagesPerConnection = 64
	defer a.FlushAll()
	packetDir := filepath.Join(s.dir, "packets")
	if err := os.MkdirAll(packetDir, 0700); err != nil {
		return err
	}
	if input == "" {
		if _, err := h.Stats(); err != nil {
			s.gap("pcap", iface, "drop_counter_unavailable", "sources", 1)
		}
		s.packetSourceState(iface, "ready")
		defer s.packetSourceState(iface, "stopped")
	}
	ring := packetRing{dir: packetDir, iface: iface, link: h.LinkType(), snaplen: uint32(h.SnapLen())}
	defer func() {
		if ring.file != nil {
			if err := ring.close(); err != nil {
				s.fail(fmt.Errorf("close packet evidence: %w", err))
			}
		}
	}()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		data, ci, e := h.ReadPacketData()
		if e == pcap.NextErrorTimeoutExpired {
			if input == "" && time.Since(last) > time.Second {
				if ring.buffer != nil {
					if err := ring.buffer.Flush(); err != nil {
						return err
					}
				}
				a.FlushOlderThan(time.Now().Add(-60 * time.Second))
				last = time.Now()
			}
			continue
		}
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			if input != "" && e.Error() == "EOF" {
				return nil
			}
			return e
		}
		{
			if e = ring.write(ci, data); e != nil {
				return e
			}
		}
		s.mu.Lock()
		s.stats.Packets++
		s.mu.Unlock()
		if ci.CaptureLength < ci.Length {
			s.gap("pcap", iface, "snapshot_truncated", "packets", 1)
		}
		pkt := gopacket.NewPacket(data, h.LinkType(), gopacket.NoCopy)
		if l := pkt.Layer(layers.LayerTypeTCP); l != nil && pkt.NetworkLayer() != nil {
			a.AssembleWithTimestamp(pkt.NetworkLayer().NetworkFlow(), l.(*layers.TCP), ci.Timestamp)
		}
		if time.Since(last) > time.Second {
			if err := ring.buffer.Flush(); err != nil {
				return err
			}
			a.FlushOlderThan(ci.Timestamp.Add(-60 * time.Second))
			if st, e := h.Stats(); e == nil {
				s.recordPacketDrops(iface, uint64(st.PacketsDropped+st.PacketsIfDropped))
			}
			last = time.Now()
		}
	}
}

func (s *Store) packetSourceState(iface, state string) {
	s.mu.Lock()
	if s.stats.PacketInterfaces == nil {
		s.stats.PacketInterfaces = map[string]string{}
	}
	s.stats.PacketInterfaces[iface] = state
	ready := true
	for _, value := range s.stats.PacketInterfaces {
		ready = ready && value == "ready"
	}
	if ready && s.stats.State == "starting" {
		s.stats.State = "running"
	}
	s.mu.Unlock()
	s.report()
}
