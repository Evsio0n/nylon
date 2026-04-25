package core

import (
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func TestComputeSysRouteTable_ExitNodeDefaultsAreLocalCaptureOnly(t *testing.T) {
	r := &NylonRouter{
		State: &state.State{
			Env: &state.Env{
				LocalCfg: state.LocalCfg{Id: "node-a"},
			},
		},
	}
	r.RouterState = &state.RouterState{
		Id: "node-a",
		Routes: map[netip.Prefix]state.SelRoute{
			netip.MustParsePrefix("10.0.0.2/32"): {
				PubRoute: state.PubRoute{
					Source: state.Source{
						NodeId: "node-b",
						Prefix: netip.MustParsePrefix("10.0.0.2/32"),
					},
				},
				Nh: "node-b",
			},
		},
	}

	assert.ElementsMatch(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.2/32"),
	}, r.ComputeSysRouteTable())

	r.LocalCfg.ExitNode = "node-exit"
	r.LocalCfg.ExcludeIPs = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	routes := r.ComputeSysRouteTable()

	assert.True(t, prefixListContainsAddr(routes, netip.MustParseAddr("10.0.0.2")))
	assert.NotContains(t, routes, netip.MustParsePrefix("192.168.0.0/16"))
	assert.NotContains(t, routes, netip.MustParsePrefix("0.0.0.0/0"))
	for _, route := range routes {
		assert.False(t, route.Contains(netip.MustParseAddr("192.168.1.1")), route.String())
	}
}

func prefixListContainsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
