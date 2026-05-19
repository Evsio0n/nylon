package state

import (
	"net/netip"

	"go4.org/netipx"
)

func SubtractPrefix(prefixes, excludes []netip.Prefix) []netip.Prefix {
	final := netipSetBuilder(prefixes)
	excludeSet := netipSetBuilder(excludes)
	set, _ := excludeSet.IPSet()
	final.RemoveSet(set)
	res, _ := final.IPSet()
	return res.Prefixes()
}

func CoalescePrefix(prefixes []netip.Prefix) []netip.Prefix {
	builder := netipSetBuilder(prefixes)
	res, _ := builder.IPSet()
	return res.Prefixes()
}

func netipSetBuilder(prefixes []netip.Prefix) netipx.IPSetBuilder {
	builder := netipx.IPSetBuilder{}
	for _, prefix := range prefixes {
		if prefix.IsValid() {
			builder.AddPrefix(prefix.Masked())
		}
	}
	return builder
}
