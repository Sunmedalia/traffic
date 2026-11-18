package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

// pcapLiveHandle is a libpcap handle that remembers whether it had to fall
// back to the libpcap default buffer.
type pcapLiveHandle struct {
	*pcap.Handle
	fallback error
}

func (h *pcapLiveHandle) bufferFallback() error { return h.fallback }

// openPCAPLive opens a libpcap interface with an explicit kernel buffer.
// pcap.OpenLive cannot set one. If the kernel refuses the requested size the
// capture still starts on the libpcap default and the shortfall is reported,
// rather than failing an incident capture outright.
func openPCAPLive(iface string) (*pcapLiveHandle, error) {
	handle, err := activatePCAP(iface, pcapBufferMiB<<20)
	if err == nil {
		return &pcapLiveHandle{Handle: handle}, nil
	}
	fallback, fallbackErr := activatePCAP(iface, 0)
	if fallbackErr != nil {
		return nil, fmt.Errorf("open %s with %d MiB capture buffer: %w", iface, pcapBufferMiB, err)
	}
	return &pcapLiveHandle{Handle: fallback, fallback: fmt.Errorf("%s: %d MiB capture buffer refused, using libpcap default: %w", iface, pcapBufferMiB, err)}, nil
}

// activatePCAP activates iface; bufferBytes 0 keeps the libpcap default.
func activatePCAP(iface string, bufferBytes int) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()
	for _, set := range []func() error{
		func() error { return inactive.SetSnapLen(int(captureSnapshotLength())) },
		func() error { return inactive.SetPromisc(false) },
		func() error { return inactive.SetTimeout(100 * time.Millisecond) },
	} {
		if err := set(); err != nil {
			return nil, err
		}
	}
	if bufferBytes > 0 {
		if err := inactive.SetBufferSize(bufferBytes); err != nil {
			return nil, err
		}
	}
	return inactive.Activate()
}
