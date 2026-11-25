package replay

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/Sunmedalia/traffic/internal/packetio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func serializePacket(t *testing.T, stack ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	checksums := false
	for _, layer := range stack {
		if tcp, ok := layer.(*layers.TCP); ok {
			for _, network := range stack {
				if n, ok := network.(gopacket.NetworkLayer); ok {
					_ = tcp.SetNetworkLayerForChecksum(n)
					checksums = true
				}
			}
		}
	}
	// A bare TCP header serialized as an extension header's payload has no
	// network layer to checksum against.
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: checksums}, stack...); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func TestPacketDecoderMatchesFullDecoder(t *testing.T) {
	v4src, v4dst := net.ParseIP("192.0.2.4").To4(), net.ParseIP("192.0.2.5").To4()
	v6src, v6dst := net.ParseIP("2001:db8::4"), net.ParseIP("2001:db8::5")
	eth := func(kind layers.EthernetType) *layers.Ethernet {
		return &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: kind}
	}
	ip4 := func(protocol layers.IPProtocol) *layers.IPv4 {
		return &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: protocol, SrcIP: v4src, DstIP: v4dst}
	}
	ip6 := func(next layers.IPProtocol) *layers.IPv6 {
		return &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: next, SrcIP: v6src, DstIP: v6dst}
	}
	tcp := func() *layers.TCP {
		return &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: 7, ACK: true, PSH: true, Window: 512, Options: []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{5, 0xb4}}}}
	}
	payload := gopacket.Payload("GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	v4 := serializePacket(t, ip4(layers.IPProtocolTCP), tcp(), payload)
	v6 := serializePacket(t, ip6(layers.IPProtocolTCP), tcp(), payload)
	sll := func(kind layers.EthernetType, inner []byte) []byte {
		header := make([]byte, 16)
		binary.BigEndian.PutUint16(header[2:], 1)
		binary.BigEndian.PutUint16(header[4:], 6)
		binary.BigEndian.PutUint16(header[14:], uint16(kind))
		return append(header, inner...)
	}
	sll2 := func(kind layers.EthernetType, inner []byte) []byte {
		header := make([]byte, 20)
		binary.BigEndian.PutUint16(header[:2], uint16(kind))
		return append(header, inner...)
	}
	hopByHop := append([]byte{byte(layers.IPProtocolTCP), 0, 1, 4, 0, 0, 0, 0}, serializePacket(t, tcp(), payload)...)
	v6hop := serializePacket(t, ip6(layers.IPProtocolIPv6HopByHop), gopacket.Payload(hopByHop))
	routing := append([]byte{byte(layers.IPProtocolTCP), 0, 0, 0, 0, 0, 0, 0}, serializePacket(t, tcp(), payload)...)
	v6routing := serializePacket(t, ip6(layers.IPProtocolIPv6Routing), gopacket.Payload(routing))
	truncated := bytes.Clone(v4[:20+12])
	binary.BigEndian.PutUint16(truncated[2:], uint16(len(truncated)))
	cases := []struct {
		name     string
		link     uint32
		data     []byte
		fast     bool
		wantTCP  bool
		wantFlow string
	}{
		{"ethernet-ipv4", uint32(layers.LinkTypeEthernet), serializePacket(t, eth(layers.EthernetTypeIPv4), ip4(layers.IPProtocolTCP), tcp(), payload), true, true, "192.0.2.4->192.0.2.5"},
		{"ethernet-vlan-ipv6", uint32(layers.LinkTypeEthernet), serializePacket(t, eth(layers.EthernetTypeDot1Q), &layers.Dot1Q{VLANIdentifier: 7, Type: layers.EthernetTypeIPv6}, ip6(layers.IPProtocolTCP), tcp(), payload), true, true, "2001:db8::4->2001:db8::5"},
		{"ipv6-hop-by-hop", uint32(layers.LinkTypeRaw), v6hop, true, true, "2001:db8::4->2001:db8::5"},
		{"linux-sll", uint32(layers.LinkTypeLinuxSLL), sll(layers.EthernetTypeIPv4, v4), true, true, "192.0.2.4->192.0.2.5"},
		{"linux-sll2", packetio.LinuxSLL2, sll2(layers.EthernetTypeIPv6, v6), true, true, "2001:db8::4->2001:db8::5"},
		{"raw-ipv4", uint32(layers.LinkTypeRaw), v4, true, true, "192.0.2.4->192.0.2.5"},
		{"loopback", uint32(layers.LinkTypeNull), serializePacket(t, &layers.Loopback{Family: layers.ProtocolFamilyIPv4}, ip4(layers.IPProtocolTCP), tcp(), payload), true, true, "192.0.2.4->192.0.2.5"},
		{"udp", uint32(layers.LinkTypeRaw), serializePacket(t, ip4(layers.IPProtocolUDP), &layers.UDP{SrcPort: 1, DstPort: 2}, payload), false, false, ""},
		{"ipv6-routing-header", uint32(layers.LinkTypeRaw), v6routing, false, true, "2001:db8::4->2001:db8::5"},
		{"ipv4-in-ipv6", uint32(layers.LinkTypeRaw), serializePacket(t, ip6(layers.IPProtocolIPv4), ip4(layers.IPProtocolTCP), tcp(), payload), false, true, "2001:db8::4->2001:db8::5"},
		{"truncated-tcp", uint32(layers.LinkTypeRaw), truncated, false, true, "192.0.2.4->192.0.2.5"},
		{"sll2-arp", packetio.LinuxSLL2, sll2(layers.EthernetTypeARP, make([]byte, 28)), false, false, ""},
	}
	d := newPacketDecoder()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := d.fallbacks
			flow, got, ok := d.decodeTCP(c.data, c.link)
			if fast := d.fallbacks == before; fast != c.fast {
				t.Fatalf("fast path %v, want %v", fast, c.fast)
			}
			full := packetio.Decode(c.data, c.link)
			want, wantOK := full.Layer(layers.LayerTypeTCP).(*layers.TCP)
			wantOK = wantOK && full.NetworkLayer() != nil
			if ok != wantOK || ok != c.wantTCP {
				t.Fatalf("decoded TCP %v, full decoder %v, want %v", ok, wantOK, c.wantTCP)
			}
			if !ok {
				return
			}
			if flow != full.NetworkLayer().NetworkFlow() || flow.String() != c.wantFlow {
				t.Fatalf("flow %v, full decoder %v", flow, full.NetworkLayer().NetworkFlow())
			}
			if got.TransportFlow() != want.TransportFlow() || got.Seq != want.Seq || got.SYN != want.SYN || got.FIN != want.FIN || got.RST != want.RST || got.ACK != want.ACK || !bytes.Equal(got.Payload, want.Payload) {
				t.Fatalf("TCP %+v, full decoder %+v", got, want)
			}
		})
	}
}

// Reused layers must not carry state from one packet into the next.
func TestPacketDecoderResetsReusedLayers(t *testing.T) {
	d := newPacketDecoder()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IP{192, 0, 2, 4}, DstIP: net.IP{192, 0, 2, 5}}
	withData := serializePacket(t, ip, &layers.TCP{SrcPort: 1, DstPort: 80, SYN: true}, gopacket.Payload("body"))
	empty := serializePacket(t, ip, &layers.TCP{SrcPort: 2, DstPort: 80, ACK: true})
	if _, tcp, ok := d.decodeTCP(withData, uint32(layers.LinkTypeRaw)); !ok || string(tcp.Payload) != "body" || !tcp.SYN {
		t.Fatal("first packet", tcp)
	}
	if _, tcp, ok := d.decodeTCP(empty, uint32(layers.LinkTypeRaw)); !ok || len(tcp.Payload) != 0 || tcp.SYN || !tcp.ACK || tcp.SrcPort != 2 {
		t.Fatal("second packet kept state from the first", tcp)
	}
}

func TestPacketDecoderFastPathDoesNotAllocate(t *testing.T) {
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IP{192, 0, 2, 4}, DstIP: net.IP{192, 0, 2, 5}}
	data := serializePacket(t, &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}, ip, &layers.TCP{SrcPort: 40000, DstPort: 80, ACK: true}, gopacket.Payload("GET / HTTP/1.1\r\n\r\n"))
	d := newPacketDecoder()
	d.decodeTCP(data, uint32(layers.LinkTypeEthernet))
	if allocs := testing.AllocsPerRun(100, func() { d.decodeTCP(data, uint32(layers.LinkTypeEthernet)) }); allocs != 0 || d.fallbacks != 0 {
		t.Fatal("fast path allocated", allocs, d.fallbacks)
	}
}

func BenchmarkPacketDecode(b *testing.B) {
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IP{192, 0, 2, 4}, DstIP: net.IP{192, 0, 2, 5}}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 80, ACK: true, PSH: true}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, gopacket.Payload(bytes.Repeat([]byte("x"), 512))); err != nil {
		b.Fatal(err)
	}
	data := buf.Bytes()
	link := uint32(layers.LinkTypeEthernet)
	b.Run("full_packet", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			packet := packetio.Decode(data, link)
			if _, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); !ok || packet.NetworkLayer() == nil {
				b.Fatal("no TCP")
			}
			_ = packet.NetworkLayer().NetworkFlow()
		}
	})
	b.Run("decoding_layer_parser", func(b *testing.B) {
		d := newPacketDecoder()
		b.ReportAllocs()
		for b.Loop() {
			if _, _, ok := d.decodeTCP(data, link); !ok {
				b.Fatal("no TCP")
			}
		}
	})
}
