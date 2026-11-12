package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

var trustedProxies []netip.Prefix

func parseTrustedProxies(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	if strings.TrimSpace(value) == "" {
		return prefixes, nil
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			address, addressErr := netip.ParseAddr(item)
			if addressErr != nil || address.Zone() != "" {
				return nil, fmt.Errorf("invalid trusted proxy %q", item)
			}
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func trustedProxy(address netip.Addr) bool {
	for _, prefix := range trustedProxies {
		if prefix.Contains(address.Unmap()) {
			return true
		}
	}
	return false
}

// Walk the chain from the socket peer to the first untrusted hop. An invalid
// chain leaves the transport identity intact so malformed headers cannot bypass trust.
func resolveClient(t *Transaction) {
	if t.PeerClient != "" || len(trustedProxies) == 0 {
		return
	}
	host, _, err := net.SplitHostPort(t.Client)
	if err != nil {
		return
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !trustedProxy(peer) {
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(t.Request)))
	if err != nil {
		return
	}
	request.Body.Close()
	values, forwarded := request.Header["X-Forwarded-For"]
	source := "x-forwarded-for"
	if !forwarded {
		values = request.Header.Values("X-Real-Ip")
		source = "x-real-ip"
		if len(values) != 1 {
			return
		}
	}
	chain := strings.Split(strings.Join(values, ","), ",")
	if len(chain) > 64 || (!forwarded && len(chain) != 1) {
		return
	}
	addresses := make([]netip.Addr, len(chain))
	for i, value := range chain {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(value))
		if parseErr != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return
		}
		addresses[i] = address.Unmap()
	}
	client := peer
	for i := len(addresses) - 1; i >= 0 && trustedProxy(client); i-- {
		client = addresses[i]
	}
	t.PeerClient = t.Client
	// Forwarding headers carry no original source port. Zero denotes unknown.
	t.Client = net.JoinHostPort(client.String(), "0")
	t.ClientSource = source
}
