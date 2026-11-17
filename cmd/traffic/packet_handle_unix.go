//go:build !windows

package main

import (
	"context"
	"github.com/google/gopacket/pcap"
	"time"
)

func listCaptureDevices() ([]pcap.Interface, error)          { return pcap.FindAllDevs() }
func bundledPacketInterfaces(string) ([]string, bool, error) { return nil, false, nil }
func openLivePacket(_ context.Context, iface string) (packetHandle, error) {
	var handle *pcap.Handle
	err := inCaptureNamespace(func() error {
		var err error
		handle, err = pcap.OpenLive(iface, captureSnapshotLength(), false, 100*time.Millisecond)
		return err
	})
	return handle, err
}
