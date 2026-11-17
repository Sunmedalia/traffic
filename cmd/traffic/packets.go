package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

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
		r.index++
		name := filepath.Join(r.dir, fmt.Sprintf("%s-%012d.pcap", packetInterfaceName(r.iface), r.index))
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
func capturePackets(ctx context.Context, s *Store, p *eventRecorder, iface, filter, input string) error {
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
	if input != "" {
		if err := checkDisk(s); err != nil {
			return err
		}
	}
	var importedBytes int64
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
			if input != "" {
				importedBytes += int64(len(data)) + 16
				if importedBytes >= 1<<20 || time.Since(last) > time.Second {
					if e = checkDisk(s); e != nil {
						return e
					}
					importedBytes = 0
				}
			}
		}
		s.mu.Lock()
		s.stats.Packets++
		s.mu.Unlock()
		if ci.CaptureLength < ci.Length {
			s.gap("pcap", iface, "snapshot_truncated", "packets", 1)
		}
		if time.Since(last) > time.Second {
			if err := ring.buffer.Flush(); err != nil {
				return err
			}
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
