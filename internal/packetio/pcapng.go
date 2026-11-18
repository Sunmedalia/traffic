package packetio

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/bits"
	"time"

	"github.com/google/gopacket"
)

const (
	sectionHeader   = 0x0a0d0d0a
	interfaceBlock  = 1
	obsoletePacket  = 2
	simplePacket    = 3
	enhancedPacket  = 6
	maxNGInterfaces = 64
	maxNGBlock      = maxSnapshot + (64 << 10)
)

type ngInterface struct {
	link, snap uint32
	index      int
	resolution uint64
	offset     int64
}

type ngReader struct {
	in         *bufio.Reader
	order      binary.ByteOrder
	interfaces []ngInterface
	nextIndex  int
	storage    []byte
}

func newNGReader(in *bufio.Reader) (*ngReader, error) {
	r := &ngReader{in: in}
	_, _, err := r.block()
	if err != nil {
		return nil, fmt.Errorf("PCAPNG section header: %w", err)
	}
	return r, nil
}

func (r *ngReader) block() (uint32, []byte, error) {
	var header [12]byte
	if _, err := io.ReadFull(r.in, header[:8]); err != nil {
		return 0, nil, err
	}
	headerSize := 8
	section := binary.LittleEndian.Uint32(header[:4]) == sectionHeader
	if section {
		if _, err := io.ReadFull(r.in, header[8:12]); err != nil {
			return 0, nil, partialRecord(err)
		}
		switch {
		case bytes.Equal(header[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a}):
			r.order = binary.LittleEndian
		case bytes.Equal(header[8:12], []byte{0x1a, 0x2b, 0x3c, 0x4d}):
			r.order = binary.BigEndian
		default:
			return 0, nil, fmt.Errorf("invalid PCAPNG byte order")
		}
		headerSize = 12
	}
	kind := r.order.Uint32(header[:4])
	size := int(r.order.Uint32(header[4:8]))
	if size < headerSize+4 || size > maxNGBlock || size%4 != 0 {
		return 0, nil, fmt.Errorf("invalid PCAPNG block size %d", size)
	}
	remaining := size - headerSize
	if cap(r.storage) < remaining {
		r.storage = make([]byte, remaining)
	}
	data := r.storage[:remaining]
	if _, err := io.ReadFull(r.in, data); err != nil {
		return 0, nil, partialRecord(err)
	}
	if r.order.Uint32(data[len(data)-4:]) != uint32(size) {
		return 0, nil, fmt.Errorf("PCAPNG block size footer does not match")
	}
	data = data[:len(data)-4]
	if section {
		if len(data) < 12 || r.order.Uint16(data[:2]) != 1 {
			return 0, nil, fmt.Errorf("unsupported PCAPNG section version")
		}
		r.interfaces = r.interfaces[:0]
	}
	return kind, data, nil
}

func partialRecord(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func (r *ngReader) addInterface(data []byte) error {
	if len(data) < 8 || r.nextIndex >= maxNGInterfaces {
		return fmt.Errorf("invalid PCAPNG interface block or interface limit exceeded")
	}
	iface := ngInterface{link: uint32(r.order.Uint16(data[:2])), snap: r.order.Uint32(data[4:8]), index: r.nextIndex, resolution: 1_000_000}
	if iface.snap == 0 {
		iface.snap = maxSnapshot
	}
	if err := validateFormat(iface.link, iface.snap); err != nil {
		return err
	}
	for options := data[8:]; len(options) > 0; {
		if len(options) < 4 {
			return fmt.Errorf("short PCAPNG interface option")
		}
		code, size := r.order.Uint16(options[:2]), int(r.order.Uint16(options[2:4]))
		if code == 0 {
			break
		}
		padded := (size + 3) &^ 3
		if len(options) < 4+padded {
			return fmt.Errorf("short PCAPNG interface option value")
		}
		value := options[4 : 4+size]
		switch code {
		case 9: // if_tsresol
			if size != 1 {
				return fmt.Errorf("invalid PCAPNG timestamp resolution")
			}
			if value[0]&0x80 != 0 {
				exponent := value[0] & 0x7f
				if exponent > 63 {
					return fmt.Errorf("unsupported PCAPNG binary timestamp resolution")
				}
				iface.resolution = uint64(1) << exponent
			} else {
				if value[0] > 19 {
					return fmt.Errorf("unsupported PCAPNG decimal timestamp resolution")
				}
				iface.resolution = 1
				for range value[0] {
					iface.resolution *= 10
				}
			}
		case 14: // if_tsoffset
			if size != 8 {
				return fmt.Errorf("invalid PCAPNG timestamp offset")
			}
			iface.offset = int64(r.order.Uint64(value))
		}
		options = options[4+padded:]
	}
	r.interfaces = append(r.interfaces, iface)
	r.nextIndex++
	return nil
}

func (r *ngReader) readPacket() ([]byte, gopacket.CaptureInfo, ngInterface, error) {
	var info gopacket.CaptureInfo
	var iface ngInterface
	for {
		kind, data, err := r.block()
		if err != nil {
			return nil, info, iface, err
		}
		switch kind {
		case interfaceBlock:
			if err := r.addInterface(data); err != nil {
				return nil, info, iface, err
			}
			continue
		case simplePacket, obsoletePacket, enhancedPacket:
			return r.packet(kind, data)
		}
	}
}

func (r *ngReader) packet(kind uint32, data []byte) ([]byte, gopacket.CaptureInfo, ngInterface, error) {
	var info gopacket.CaptureInfo
	var iface ngInterface
	var index uint32
	size := 4
	if kind != simplePacket {
		size = 20
	}
	if len(data) < size {
		return nil, info, iface, fmt.Errorf("short PCAPNG packet header")
	}
	switch kind {
	case obsoletePacket:
		index = uint32(r.order.Uint16(data[:2]))
	case enhancedPacket:
		index = r.order.Uint32(data[:4])
	}
	if index >= uint32(len(r.interfaces)) {
		return nil, info, iface, fmt.Errorf("PCAPNG packet references unknown interface %d", index)
	}
	iface = r.interfaces[index]
	info.InterfaceIndex = iface.index
	if kind == simplePacket {
		info.Timestamp = time.Unix(0, 0).UTC() // Simple Packet Blocks have no timestamp.
		info.Length = int(r.order.Uint32(data[:4]))
		info.CaptureLength = min(info.Length, int(iface.snap))
	} else {
		ticks := uint64(r.order.Uint32(data[4:8]))<<32 | uint64(r.order.Uint32(data[8:12]))
		seconds := ticks / iface.resolution
		if seconds > math.MaxInt64 || (iface.offset > 0 && seconds > uint64(math.MaxInt64-iface.offset)) {
			return nil, info, iface, fmt.Errorf("PCAPNG packet timestamp overflow")
		}
		high, low := bits.Mul64(ticks%iface.resolution, 1_000_000_000)
		nanos, _ := bits.Div64(high, low, iface.resolution)
		info.Timestamp = time.Unix(int64(seconds)+iface.offset, int64(nanos)).UTC()
		info.CaptureLength = int(r.order.Uint32(data[12:16]))
		info.Length = int(r.order.Uint32(data[16:20]))
	}
	if info.CaptureLength < 0 || info.CaptureLength > info.Length || info.CaptureLength > int(iface.snap) || (info.CaptureLength+3)&^3 > len(data)-size {
		return nil, info, iface, fmt.Errorf("invalid PCAPNG packet length %d (wire length %d)", info.CaptureLength, info.Length)
	}
	return bytes.Clone(data[size : size+info.CaptureLength]), info, iface, nil
}
