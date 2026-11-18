//go:build !windows

package main

import (
	"context"
	"github.com/google/gopacket/pcap"
)

func listCaptureDevices() ([]pcap.Interface, error)          { return pcap.FindAllDevs() }
func bundledPacketInterfaces(string) ([]string, bool, error) { return nil, false, nil }
func openLivePacket(_ context.Context, iface string) (packetHandle, error) {
	var handle *pcapLiveHandle
	err := inCaptureNamespace(func() error {
		var err error
		handle, err = openPCAPLive(iface)
		return err
	})
	if err != nil {
		return nil, err
	}
	return handle, nil
}
