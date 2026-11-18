package main

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/google/gopacket"
)

const winDivertAddrSize = 80
const winDivertBatchMax = 64

type winDivertBatchPacket struct {
	data []byte
	ci   gopacket.CaptureInfo
}

// qpcTicksToUTC converts a WinDivert WINDIVERT_ADDRESS QueryPerformanceCounter
// tick value to UTC wall-clock time using an anchor sampled at handle open.
func qpcTicksToUTC(ticks, anchorTicks, freq int64, anchorUTC time.Time) time.Time {
	if ticks <= 0 || anchorTicks <= 0 || freq <= 0 || freq > 9_000_000_000 || anchorUTC.IsZero() {
		return time.Time{}
	}
	delta := ticks - anchorTicks
	sec := delta / freq
	const maxSeconds = int64((1<<63-1)/int64(time.Second)) - 1
	if sec < -maxSeconds || sec > maxSeconds {
		return time.Time{}
	}
	rem := delta % freq
	return anchorUTC.Add(time.Duration(sec)*time.Second + time.Duration((rem*int64(time.Second))/freq)).UTC()
}

// WinDivert timestamps precede completion of the receive. Reject a conversion
// outside the lifetime of the handle or well past the receive wall clock.
func winDivertPacketTime(ticks, anchorTicks, freq int64, anchorUTC, receivedAt time.Time) (time.Time, bool) {
	converted := qpcTicksToUTC(ticks, anchorTicks, freq, anchorUTC)
	if converted.IsZero() || converted.Before(anchorUTC.Add(-time.Millisecond)) ||
		converted.After(receivedAt.Add(100*time.Millisecond)) ||
		receivedAt.Sub(converted) > 16*time.Second {
		return receivedAt.UTC(), false
	}
	return converted, true
}

func winDivertIPLength(packet []byte) (int, error) {
	switch packet[0] >> 4 {
	case 4:
		header := int(packet[0]&0x0f) * 4
		if header < 20 || header > len(packet) {
			return 0, errors.New("invalid IPv4 header in WinDivert batch")
		}
		length := int(binary.BigEndian.Uint16(packet[2:4]))
		if length < header || length > len(packet) {
			return 0, errors.New("invalid IPv4 total length in WinDivert batch")
		}
		return length, nil
	case 6:
		if len(packet) < 40 {
			return 0, errors.New("truncated IPv6 header in WinDivert batch")
		}
		length := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if length > len(packet) {
			return 0, errors.New("invalid IPv6 payload length in WinDivert batch")
		}
		return length, nil
	default:
		return 0, errors.New("unknown IP version in WinDivert batch")
	}
}

// splitWinDivertBatch validates the complete byte and address layout before
// exposing packets. Each address must match exactly one IP packet, including
// the final packet and single-packet receives.
func splitWinDivertBatch(buf []byte, recvLen uint32, addrBuf []byte, addrLen uint32, snaplen int, toUTC func(int64) time.Time) ([]winDivertBatchPacket, error) {
	if uint64(recvLen) > uint64(len(buf)) {
		return nil, errors.New("invalid WinDivert packet length")
	}
	if recvLen == 0 && addrLen == 0 {
		return nil, nil
	}
	if uint64(addrLen) > uint64(len(addrBuf)) || addrLen == 0 || addrLen%winDivertAddrSize != 0 || addrLen/winDivertAddrSize > winDivertBatchMax {
		return nil, errors.New("invalid WinDivert address array length")
	}
	count := int(addrLen) / winDivertAddrSize
	raw := buf[:recvLen]
	var lengths [winDivertBatchMax]int
	for i := range count {
		if len(raw) == 0 {
			return nil, errors.New("WinDivert address has no matching packet")
		}
		length, err := winDivertIPLength(raw)
		if err != nil {
			return nil, err
		}
		lengths[i] = length
		raw = raw[length:]
	}
	if len(raw) != 0 {
		return nil, errors.New("WinDivert packet bytes remain after last address")
	}
	if snaplen <= 0 {
		snaplen = len(buf)
	}
	receivedAt := time.Now().UTC()
	raw = buf[:recvLen]
	out := make([]winDivertBatchPacket, 0, count)
	for i, length := range lengths[:count] {
		stamp := receivedAt
		if toUTC != nil {
			offset := i * winDivertAddrSize
			ticks := int64(binary.LittleEndian.Uint64(addrBuf[offset : offset+8]))
			if converted := toUTC(ticks); !converted.IsZero() {
				stamp = converted
			}
		}
		data := append([]byte(nil), raw[:min(length, snaplen)]...)
		out = append(out, winDivertBatchPacket{data: data,
			ci: gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: len(data), Length: length}})
		raw = raw[length:]
	}
	return out, nil
}
