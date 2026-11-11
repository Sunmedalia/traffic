package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	directions map[string]bool
	id         uint64
}
type streamFactory struct {
	generations map[string]*streamGeneration
	p           *HTTPProcessor
	source      string
}

func (f *streamFactory) New(n, t gopacket.Flow) tcpassembly.Stream {
	r := queuedStream{chunks: make(chan []byte, 16), store: f.p.s}
	ends := []string{net.JoinHostPort(n.Src().String(), t.Src().String()), net.JoinHostPort(n.Dst().String(), t.Dst().String())}
	client := ends[0]
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
	select {
	case f.p.slots <- struct{}{}:
	default:
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
	writer     *pcapgo.Writer
	size       int64
	index      int
	link       layers.LinkType
}

func (r *packetRing) write(ci gopacket.CaptureInfo, b []byte) error {
	if r.file == nil || r.size+int64(len(b))+16 > 64<<20 {
		if r.file != nil {
			r.file.Close()
		}
		r.index = (r.index + 1) % 16
		name := filepath.Join(r.dir, fmt.Sprintf("packets-%s-%02d.pcap", r.iface, r.index))
		f, e := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		r.file = f
		r.writer = pcapgo.NewWriter(f)
		if e = r.writer.WriteFileHeader(65535, r.link); e != nil {
			return e
		}
		r.size = 24
	}
	e := r.writer.WritePacket(ci, b)
	r.size += int64(len(b)) + 16
	return e
}
func capturePackets(ctx context.Context, s *Store, p *HTTPProcessor, iface, filter, input string) error {
	var h *pcap.Handle
	var e error
	if input != "" {
		h, e = pcap.OpenOffline(input)
	} else {
		h, e = pcap.OpenLive(iface, 65535, false, 100*time.Millisecond)
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
	ring := packetRing{dir: s.dir, iface: iface, link: h.LinkType()}
	defer func() {
		if ring.file != nil {
			ring.file.Close()
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
				a.FlushOlderThan(time.Now().Add(-60 * time.Second))
				last = time.Now()
			}
			continue
		}
		if e != nil {
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
		pkt := gopacket.NewPacket(data, h.LinkType(), gopacket.NoCopy)
		if l := pkt.Layer(layers.LayerTypeTCP); l != nil && pkt.NetworkLayer() != nil {
			a.AssembleWithTimestamp(pkt.NetworkLayer().NetworkFlow(), l.(*layers.TCP), ci.Timestamp)
		}
		if time.Since(last) > time.Second {
			a.FlushOlderThan(ci.Timestamp.Add(-60 * time.Second))
			if st, e := h.Stats(); e == nil {
				s.recordPacketDrops(iface, uint64(st.PacketsDropped+st.PacketsIfDropped))
			}
			last = time.Now()
		}
	}
}
