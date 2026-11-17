package main

import (
	"fmt"
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
