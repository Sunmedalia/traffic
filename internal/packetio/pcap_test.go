package packetio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestWideLinkTypeAndTornPacketBody(t *testing.T) {
	var capture bytes.Buffer
	if err := WriteHeader(&capture, 256<<10, LinuxSLL2); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 40)
	binary.BigEndian.PutUint16(data[:2], uint16(layers.EthernetTypeIPv4))
	data[20], data[22], data[23] = 0x45, 0, 20
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(1, 123456789), CaptureLength: len(data), Length: len(data)}
	if err := pcapgo.NewWriterNanos(&capture).WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	wire := capture.Bytes()
	for cut := 24; cut <= len(wire); cut++ {
		reader, err := NewReader(bytes.NewReader(wire[:cut]))
		if err != nil || reader.Link != LinuxSLL2 {
			t.Fatalf("wide link type missing at offset %d: %v, %v", cut, reader, err)
		}
		decoded, info, err := reader.ReadPacketData()
		switch cut {
		case 24:
			if err != io.EOF {
				t.Fatalf("empty capture: %v", err)
			}
		case len(wire):
			if err != nil || !info.Timestamp.Equal(ci.Timestamp) || !bytes.Equal(decoded, data) || Decode(decoded, reader.Link).NetworkLayer() == nil {
				t.Fatalf("SLL2 round trip failed: %v %+v", err, info)
			}
		default:
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("incomplete packet at offset %d: %v", cut, err)
			}
		}
	}
	// The low byte is Ethernet, but the full on-disk value is unsupported.
	binary.LittleEndian.PutUint32(wire[20:24], 257)
	if _, err := NewReader(bytes.NewReader(wire)); err == nil {
		t.Fatal("unknown link type was narrowed to Ethernet")
	}
}

func TestPCAPNGPreservesInterfaceLinkTypesAndTimeResolution(t *testing.T) {
	var capture bytes.Buffer
	var nextOrder binary.ByteOrder
	writeBlock := func(kind uint32, body []byte) {
		t.Helper()
		size := uint32(12 + len(body))
		for _, value := range []uint32{kind, size} {
			if err := binary.Write(&capture, nextOrder, value); err != nil {
				t.Fatal(err)
			}
		}
		capture.Write(body)
		if err := binary.Write(&capture, nextOrder, size); err != nil {
			t.Fatal(err)
		}
	}
	writeSection := func(order binary.ByteOrder) {
		nextOrder = order
		body := make([]byte, 16)
		order.PutUint32(body, 0x1a2b3c4d)
		order.PutUint16(body[4:], 1)
		order.PutUint64(body[8:], ^uint64(0))
		writeBlock(sectionHeader, body)
	}
	writeInterface := func(link uint16, resolution byte) {
		body := make([]byte, 16)
		nextOrder.PutUint16(body, link)
		nextOrder.PutUint32(body[4:], 65535)
		nextOrder.PutUint16(body[8:], 9)
		nextOrder.PutUint16(body[10:], 1)
		body[12] = resolution
		writeBlock(interfaceBlock, body)
	}
	writePacket := func(index, ticks uint32, value byte) {
		body := make([]byte, 24)
		nextOrder.PutUint32(body, index)
		nextOrder.PutUint32(body[8:], ticks)
		nextOrder.PutUint32(body[12:], 1)
		nextOrder.PutUint32(body[16:], 1)
		body[20] = value
		writeBlock(enhancedPacket, body)
	}

	writeSection(binary.LittleEndian)
	writeInterface(uint16(layers.LinkTypeEthernet), 6)
	writeInterface(LinuxSLL2, 0x80|10)
	writePacket(1, 1536, 1)
	writePacket(0, 1500000, 2)
	writeSection(binary.BigEndian)
	writeInterface(uint16(layers.LinkTypeLinuxSLL), 9)
	writePacket(0, 1500000000, 3)

	reader, err := NewReader(&capture)
	if err != nil {
		t.Fatal(err)
	}
	for i, expected := range []struct {
		index int
		link  uint32
	}{
		{1, LinuxSLL2}, {0, uint32(layers.LinkTypeEthernet)}, {2, uint32(layers.LinkTypeLinuxSLL)},
	} {
		data, info, err := reader.ReadPacketData()
		if err != nil || !bytes.Equal(data, []byte{byte(i + 1)}) || info.InterfaceIndex != expected.index ||
			reader.Link != expected.link || !info.Timestamp.Equal(time.Unix(1, 500000000)) {
			t.Fatalf("packet %d: link=%d, info=%+v, data=%v, err=%v", i, reader.Link, info, data, err)
		}
	}
	if _, _, err := reader.ReadPacketData(); err != io.EOF {
		t.Fatal(err)
	}
}
