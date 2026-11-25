package main

import (
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
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
func splitWinDivertBatch(buf []byte, recvLen uint32, addrBuf []byte, addrLen uint32, snaplen int, receivedAt time.Time, toUTC func(int64) time.Time) ([]winDivertBatchPacket, error) {
	if uint64(recvLen) > uint64(len(buf)) {
		return nil, errors.New("invalid WinDivert packet length")
	}
	if recvLen == 0 && addrLen == 0 {
		return nil, nil
	}
	if uint64(addrLen) > uint64(len(addrBuf)) || addrLen == 0 || addrLen%winDivertAddrSize != 0 || addrLen/winDivertAddrSize > winDivertBatchMax {
		return nil, errors.New("invalid WinDivert address array length")
	}
	if snaplen <= 0 {
		snaplen = len(buf)
	}
	count := int(addrLen) / winDivertAddrSize
	raw := buf[:recvLen]
	var lengths [winDivertBatchMax]int
	var capturedBytes int
	for i := range count {
		if len(raw) == 0 {
			return nil, errors.New("WinDivert address has no matching packet")
		}
		length, err := winDivertIPLength(raw)
		if err != nil {
			return nil, err
		}
		lengths[i] = length
		capturedBytes += min(length, snaplen)
		raw = raw[length:]
	}
	if len(raw) != 0 {
		return nil, errors.New("WinDivert packet bytes remain after last address")
	}
	slab := make([]byte, capturedBytes)
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
		captured := min(length, snaplen)
		data := slab[:captured:captured]
		copy(data, raw[:captured])
		slab = slab[captured:]
		out = append(out, winDivertBatchPacket{data: data,
			ci: gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: len(data), Length: length}})
		raw = raw[length:]
	}
	return out, nil
}

const winDivertBatchChannelCap = 256
const winDivertBatchBudgetBytes = 32 << 20

type winDivertQueuedBatch struct {
	packets []winDivertBatchPacket
	bytes   int64
}

type winDivertBatchQueue struct {
	batches    chan winDivertQueuedBatch
	batchBytes atomic.Int64
	batchSpace chan struct{}
	abortCh    <-chan struct{}
	current    winDivertQueuedBatch
	readTimer  *time.Timer
}

func newWinDivertBatchQueue(abortCh <-chan struct{}) *winDivertBatchQueue {
	return &winDivertBatchQueue{
		batches:    make(chan winDivertQueuedBatch, winDivertBatchChannelCap),
		batchSpace: make(chan struct{}, 1),
		abortCh:    abortCh,
	}
}

// Only the receive pump reserves bytes. The reader releases an entire slab
// when it hands off the last packet, so partially read batches stay charged.
func (h *winDivertBatchQueue) queueBatch(packets []winDivertBatchPacket) bool {
	batch := winDivertQueuedBatch{packets: packets}
	for _, p := range packets {
		batch.bytes += int64(len(p.data))
	}
	for h.batchBytes.Load()+batch.bytes > winDivertBatchBudgetBytes {
		select {
		case <-h.batchSpace:
		case <-h.abortCh:
			return false
		}
	}
	h.batchBytes.Add(batch.bytes)
	select {
	case h.batches <- batch:
		return true
	case <-h.abortCh:
		h.batchBytes.Add(-batch.bytes)
		return false
	}
}

func (h *winDivertBatchQueue) nextBatchPacket() ([]byte, gopacket.CaptureInfo, error) {
	pkt := h.current.packets[0]
	h.current.packets = h.current.packets[1:]
	if len(h.current.packets) == 0 {
		if h.current.bytes > 0 {
			h.batchBytes.Add(-h.current.bytes)
			select {
			case h.batchSpace <- struct{}{}:
			default:
			}
		}
		h.current = winDivertQueuedBatch{}
	}
	return pkt.data, pkt.ci, nil
}

func (h *winDivertBatchQueue) acceptBatch(batch winDivertQueuedBatch, ok bool) ([]byte, gopacket.CaptureInfo, error) {
	if !ok {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	if len(batch.packets) == 0 {
		return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
	}
	h.current = batch
	return h.nextBatchPacket()
}

func (h *winDivertBatchQueue) readPacket() ([]byte, gopacket.CaptureInfo, error) {
	if len(h.current.packets) > 0 {
		return h.nextBatchPacket()
	}
	select {
	case batch, ok := <-h.batches:
		return h.acceptBatch(batch, ok)
	default:
	}
	const wait = 100 * time.Millisecond
	if h.readTimer == nil {
		h.readTimer = time.NewTimer(wait)
	} else {
		h.readTimer.Reset(wait)
	}
	select {
	case batch, ok := <-h.batches:
		if !h.readTimer.Stop() {
			<-h.readTimer.C
		}
		return h.acceptBatch(batch, ok)
	case <-h.readTimer.C:
		// Report terminal errors only after all completed batches are consumed.
		return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
	}
}
