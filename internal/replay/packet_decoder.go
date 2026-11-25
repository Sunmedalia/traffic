package replay

import (
	"encoding/binary"

	"github.com/Sunmedalia/traffic/internal/packetio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// packetDecoder decodes the link, network and TCP headers of every packet in
// a replay into one reused set of layer structs, instead of allocating a
// gopacket.Packet and its layers per packet. It is not safe for concurrent use.
//
// The fast path covers the link types the collector writes and plain
// IPv4/IPv6 (with an inline hop-by-hop header) carrying TCP. Anything it does
// not decode end to end, such as IPv6 extension headers, tunnels or malformed
// headers, goes through packetio.Decode, so results match the full decoder.
type packetDecoder struct {
	parsers map[gopacket.LayerType]*gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
	eth     layers.Ethernet
	sll     layers.LinuxSLL
	loop    layers.Loopback
	dot1q   layers.Dot1Q
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	// fallbacks counts packets that needed the full decoder (for tests).
	fallbacks uint64
}

func newPacketDecoder() *packetDecoder {
	d := &packetDecoder{decoded: make([]gopacket.LayerType, 0, 8)}
	d.parsers = make(map[gopacket.LayerType]*gopacket.DecodingLayerParser)
	for _, first := range []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeLinuxSLL, layers.LayerTypeLoopback, layers.LayerTypeIPv4, layers.LayerTypeIPv6} {
		// Parsers share the layer structs; only the first layer differs.
		parser := gopacket.NewDecodingLayerParser(first)
		parser.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
		for _, layer := range []gopacket.DecodingLayer{&d.eth, &d.sll, &d.loop, &d.dot1q, &d.ip4, &d.ip6, &d.tcp} {
			parser.AddDecodingLayer(layer)
		}
		// The parse stops after TCP: its payload stays in tcp.Payload.
		parser.IgnoreUnsupported = true
		d.parsers[first] = parser
	}
	return d
}

// firstLayer maps a capture link type to the layer the fast path starts at
// and the link header bytes it skips. ok is false for other link types.
func firstLayer(data []byte, link uint32) (gopacket.LayerType, int, bool) {
	switch link {
	case uint32(layers.LinkTypeEthernet):
		return layers.LayerTypeEthernet, 0, true
	case uint32(layers.LinkTypeLinuxSLL):
		return layers.LayerTypeLinuxSLL, 0, true
	case uint32(layers.LinkTypeNull), uint32(layers.LinkTypeLoop):
		return layers.LayerTypeLoopback, 0, true
	case uint32(layers.LinkTypeRaw):
		if len(data) > 0 {
			switch data[0] >> 4 {
			case 4:
				return layers.LayerTypeIPv4, 0, true
			case 6:
				return layers.LayerTypeIPv6, 0, true
			}
		}
	case packetio.LinuxSLL2:
		if len(data) >= 20 {
			switch layers.EthernetType(binary.BigEndian.Uint16(data[:2])) {
			case layers.EthernetTypeIPv4:
				return layers.LayerTypeIPv4, 20, true
			case layers.EthernetTypeIPv6:
				return layers.LayerTypeIPv6, 20, true
			}
		}
	}
	return gopacket.LayerTypeZero, 0, false
}

// decodeTCP returns the network flow and TCP header of a packet. The TCP
// layer and its payload alias data and the decoder, and are valid only until
// the next call; tcpassembly copies what it keeps.
func (d *packetDecoder) decodeTCP(data []byte, link uint32) (gopacket.Flow, *layers.TCP, bool) {
	if first, offset, ok := firstLayer(data, link); ok {
		if flow, ok := d.fast(d.parsers[first], data[offset:]); ok {
			return flow, &d.tcp, true
		}
	}
	d.fallbacks++
	packet := packetio.Decode(data, link)
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || packet.NetworkLayer() == nil {
		return gopacket.Flow{}, nil, false
	}
	return packet.NetworkLayer().NetworkFlow(), tcp, true
}

// fast accepts a packet only when exactly one network layer and then TCP
// decoded without error, the case where the full decoder yields the same
// first network layer and TCP layer.
func (d *packetDecoder) fast(parser *gopacket.DecodingLayerParser, data []byte) (gopacket.Flow, bool) {
	if err := parser.DecodeLayers(data, &d.decoded); err != nil {
		return gopacket.Flow{}, false
	}
	var network gopacket.LayerType
	sawTCP := false
	for _, layer := range d.decoded {
		switch layer {
		case layers.LayerTypeIPv4, layers.LayerTypeIPv6:
			if network != gopacket.LayerTypeZero {
				return gopacket.Flow{}, false
			}
			network = layer
		case layers.LayerTypeTCP:
			sawTCP = true
		}
	}
	if !sawTCP {
		return gopacket.Flow{}, false
	}
	if network == layers.LayerTypeIPv4 {
		return d.ip4.NetworkFlow(), true
	}
	return d.ip6.NetworkFlow(), network == layers.LayerTypeIPv6
}
