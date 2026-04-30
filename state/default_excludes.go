package state

import "net/netip"

// DefaultLocalExcludes are never useful through an exit node. They should stay
// on the local link or be handled by a dedicated discovery reflector.
func DefaultLocalExcludes() []netip.Prefix {
	result := DefaultLocalIPv4Excludes()
	result = append(result,
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	)
	return result
}

func DefaultLocalIPv4Excludes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
}

func IsDefaultLocalExcludedAddr(addr netip.Addr) bool {
	for _, prefix := range DefaultLocalExcludes() {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
