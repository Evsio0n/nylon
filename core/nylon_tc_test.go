package core

import (
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func TestNodeOwnsExitSourceAddrOnlyAllowsNodeAddresses(t *testing.T) {
	cfg := state.CentralCfg{
		Routers: []state.RouterCfg{
			{
				NodeCfg: state.NodeCfg{
					Id:        "router-a",
					Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")},
					Prefixes: []state.PrefixHealthWrapper{
						{PrefixHealth: &state.StaticPrefixHealth{Prefix: netip.MustParsePrefix("10.10.0.0/24")}},
					},
				},
			},
		},
	}

	assert.True(t, nodeOwnsExitSourceAddr(&cfg, "router-a", netip.MustParseAddr("10.0.0.1")))
	assert.False(t, nodeOwnsExitSourceAddr(&cfg, "router-a", netip.MustParseAddr("10.10.0.42")))
	assert.False(t, nodeOwnsExitSourceAddr(&cfg, "router-a", netip.MustParseAddr("10.0.0.2")))
}

func TestDefaultLocalExcludedAddr(t *testing.T) {
	assert.True(t, state.IsDefaultLocalExcludedAddr(netip.MustParseAddr("224.0.0.251")))
	assert.True(t, state.IsDefaultLocalExcludedAddr(netip.MustParseAddr("239.255.255.250")))
	assert.True(t, state.IsDefaultLocalExcludedAddr(netip.MustParseAddr("169.254.10.20")))
	assert.True(t, state.IsDefaultLocalExcludedAddr(netip.MustParseAddr("ff02::fb")))
	assert.True(t, state.IsDefaultLocalExcludedAddr(netip.MustParseAddr("fe80::1")))
	assert.False(t, state.IsDefaultLocalExcludedAddr(netip.MustParseAddr("8.8.8.8")))
}
