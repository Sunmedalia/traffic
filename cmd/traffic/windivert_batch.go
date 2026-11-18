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
	rem := delta % freq
	return anchorUTC.Add(time.Duration(sec)*time.Second + time.Duration((rem*int64(time.Second))/freq)).UTC()
}

// splitWinDivertBatch slices a raw WinDivertRecvEx packet buffer using the
// returned WINDIVERT_ADDRESS array and IPv4/IPv6 header total lengths.
func splitWinDivertBatch(buf []byte, recvLen uint32, addrBuf []byte, addrLen uint32, snaplen int, toUTC func(int64) time.Time) ([]winDivertBatchPacket, error) {
	if int(recvLen) > len(buf) {
		return nil, errors.New("invalid WinDivert packet length")
	}
	if recvLen == 0 {
		return nil, nil
	}
	count := int(addrLen) / winDivertAddrSize
	if count <= 0 {
		count = 1
	}
	if snaplen <= 0 {
		snaplen = len(buf)
	}
	stampAt := func(index int) time.Time {
		offset := index * winDivertAddrSize
		if toUTC != nil && offset+8 <= int(addrLen) && offset+8 <= len(addrBuf) {
			ticks := int64(binary.LittleEndian.Uint64(addrBuf[offset : offset+8]))
			if ticks > 0 {
				if ts := toUTC(ticks); !ts.IsZero() {
					return ts
				}
			}
		}
		return time.Now().UTC()
	}

	if count == 1 {
		fullLen := int(recvLen)
		capLen := min(fullLen, snaplen)
		copied := append([]byte(nil), buf[:capLen]...)
		return []winDivertBatchPacket{{
			data: copied,
			ci:   gopacket.CaptureInfo{Timestamp: stampAt(0), CaptureLength: capLen, Length: fullLen},
		}}, nil
	}

	out := make([]winDivertBatchPacket, 0, count)
	offset := 0
	total := int(recvLen)
	for i := 0; i < count && offset < total; i++ {
		remaining := total - offset
		pktLen := remaining
		if i < count-1 {
			ver := buf[offset] >> 4
			switch ver {
			case 4:
				if remaining < 20 {
					return out, errors.New("truncated IPv4 header in WinDivert batch")
				}
				pktLen = int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
			case 6:
				if remaining < 40 {
					return out, errors.New("truncated IPv6 header in WinDivert batch")
				}
				pktLen = 40 + int(binary.BigEndian.Uint16(buf[offset+4:offset+6]))
			default:
				return out, errors.New("unknown IP version in WinDivert batch")
			}
			if pktLen <= 0 || pktLen > remaining {
				return out, errors.New("invalid packet length in WinDivert batch")
			}
		}
		capLen := min(pktLen, snaplen)
		copied := append([]byte(nil), buf[offset:offset+capLen]...)
		out = append(out, winDivertBatchPacket{
			data: copied,
			ci:   gopacket.CaptureInfo{Timestamp: stampAt(i), CaptureLength: capLen, Length: pktLen},
		})
		offset += pktLen
	}
	return out, nil
}
