package main

import (
	"bufio"
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"io"
	"os"
)

type packetHandle interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
	SnapLen() int
	SetBPFFilter(string) error
	Stats() (*pcap.Stats, error)
	Close()
}
type offlinePacketHandle struct {
	file *os.File
	read func() ([]byte, gopacket.CaptureInfo, error)
	link layers.LinkType
	snap int
}

func openOfflinePacket(path string) (packetHandle, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(file)
	magic, err := reader.Peek(4)
	if err != nil {
		file.Close()
		return nil, err
	}
	result := &offlinePacketHandle{file: file}
	if bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		ng, err := pcapgo.NewNgReader(reader, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			file.Close()
			return nil, err
		}
		result.read = ng.ReadPacketData
		result.link = ng.LinkType()
		result.snap = int(captureSnapshotLength())
	} else {
		pcap, err := pcapgo.NewReader(reader)
		if err != nil {
			file.Close()
			return nil, err
		}
		result.read = pcap.ReadPacketData
		result.link = pcap.LinkType()
		result.snap = int(pcap.Snaplen())
	}
	return result, nil
}
func (h *offlinePacketHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	for {
		data, ci, err := h.read()
		if err != nil {
			return nil, ci, err
		}
		packet := gopacket.NewPacket(data, h.link, gopacket.NoCopy)
		if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && (capturePorts[int(tcp.SrcPort)] || capturePorts[int(tcp.DstPort)] || len(capturePorts) == 0) {
			return data, ci, nil
		}
	}
}
func (h *offlinePacketHandle) LinkType() layers.LinkType   { return h.link }
func (h *offlinePacketHandle) SnapLen() int                { return h.snap }
func (h *offlinePacketHandle) SetBPFFilter(string) error   { return nil }
func (h *offlinePacketHandle) Stats() (*pcap.Stats, error) { return nil, io.EOF }
func (h *offlinePacketHandle) Close()                      { h.file.Close() }
