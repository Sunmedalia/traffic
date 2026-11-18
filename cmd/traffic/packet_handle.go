package main

import (
	"github.com/Sunmedalia/traffic/internal/packetio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"os"
	"time"
)

type packetHandle interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
	SnapLen() int
	SetBPFFilter(string) error
	Stats() (*pcap.Stats, error)
	Close()
}

type pollTimestamper interface {
	LastPollTime() time.Time
}
type offlinePacketHandle struct {
	file *os.File
	*packetio.Reader
}

func openOfflinePacket(path string) (*offlinePacketHandle, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	reader, err := packetio.NewReader(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	return &offlinePacketHandle{file: file, Reader: reader}, nil
}
func (h *offlinePacketHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	for {
		data, ci, err := h.Reader.ReadPacketData()
		if err != nil {
			return nil, ci, err
		}
		packet := packetio.Decode(data, h.Link)
		if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && (capturePorts[int(tcp.SrcPort)] || capturePorts[int(tcp.DstPort)] || len(capturePorts) == 0) {
			return data, ci, nil
		}
	}
}
func (h *offlinePacketHandle) LinkType() layers.LinkType   { return layers.LinkType(h.Link) }
func (h *offlinePacketHandle) SnapLen() int                { return int(h.Snap) }
func (h *offlinePacketHandle) SetBPFFilter(string) error   { return nil }
func (h *offlinePacketHandle) Stats() (*pcap.Stats, error) { return nil, io.EOF }
func (h *offlinePacketHandle) Close()                      { h.file.Close() }
