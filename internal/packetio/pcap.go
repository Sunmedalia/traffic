// Package packetio reads packet evidence without narrowing the on-disk link type.
package packetio

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const LinuxSLL2 = 276
const maxSnapshot = 16 << 20

type Reader struct {
	Link uint32
	Snap uint32
	ng   *ngReader
	next func() ([]byte, gopacket.CaptureInfo, error)
}

func NewReader(input io.Reader) (*Reader, error) {
	buffer := bufio.NewReader(input)
	prefix, err := buffer.Peek(2)
	if err != nil {
		return nil, fmt.Errorf("capture header: %w", err)
	}
	if prefix[0] == 0x1f && prefix[1] == 0x8b {
		compressed, err := gzip.NewReader(buffer)
		if err != nil {
			return nil, fmt.Errorf("compressed capture header: %w", err)
		}
		buffer = bufio.NewReader(compressed)
	}
	magic, err := buffer.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("capture header: %w", err)
	}
	var reader Reader
	switch {
	case bytes.Equal(magic, []byte{10, 13, 13, 10}):
		ng, err := newNGReader(buffer)
		if err != nil {
			return nil, err
		}
		return &Reader{ng: ng}, nil
	default:
		header, err := buffer.Peek(24)
		if err != nil {
			return nil, fmt.Errorf("PCAP header: %w", err)
		}
		var order binary.ByteOrder = binary.LittleEndian
		if header[0] == 0xa1 {
			order = binary.BigEndian
		}
		link := order.Uint32(header[20:24]) & 0xffff
		pcap, err := pcapgo.NewReader(buffer)
		if err != nil {
			return nil, fmt.Errorf("PCAP header: %w", err)
		}
		reader = Reader{Link: link, Snap: pcap.Snaplen(), next: pcap.ReadPacketData}
	}
	if err = validateFormat(reader.Link, reader.Snap); err != nil {
		return nil, err
	}
	return &reader, nil
}

func validateFormat(link, snap uint32) error {
	if snap == 0 || snap > maxSnapshot {
		return fmt.Errorf("unsupported capture snapshot length %d", snap)
	}
	if link != LinuxSLL2 && (link > 255 || layers.LinkTypeMetadata[link].Name == "UnknownLinkType") {
		return fmt.Errorf("unsupported capture link type %d", link)
	}
	return nil
}

func (r *Reader) IsPCAPNG() bool { return r.ng != nil }

func (r *Reader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if r.ng != nil {
		data, info, iface, err := r.ng.readPacket()
		if err == nil {
			r.Link, r.Snap = iface.link, iface.snap
		}
		return data, info, err
	}
	data, info, err := r.next()
	if err == io.EOF && info.CaptureLength > 0 {
		err = io.ErrUnexpectedEOF
	}
	return data, info, err
}

func Decode(data []byte, link uint32) gopacket.Packet {
	var decoder gopacket.Decoder = layers.LinkType(link)
	if link == LinuxSLL2 {
		decoder = gopacket.DecodeFunc(func(data []byte, builder gopacket.PacketBuilder) error {
			if len(data) < 20 {
				return fmt.Errorf("short Linux SLL2 header")
			}
			return layers.EthernetType(binary.BigEndian.Uint16(data[:2])).Decode(data[20:], builder)
		})
	}
	return gopacket.NewPacket(data, decoder, gopacket.NoCopy)
}

// WriteHeader preserves the full on-disk link type. pcapgo's packet writer
// accepts a uint8 LinkType only when it writes the file header.
func WriteHeader(w io.Writer, snap, link uint32) error {
	var header bytes.Buffer
	if err := pcapgo.NewWriterNanos(&header).WriteFileHeader(snap, layers.LinkType(link)); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(header.Bytes()[20:24], link)
	_, err := w.Write(header.Bytes())
	return err
}
