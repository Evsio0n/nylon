package mobile

import (
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/core"
	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func TestBuildTunnelRoutes_NoExitNodeOmitsDefault(t *testing.T) {
	routes := BuildTunnelRoutes(&core.Nylon{
		ConfigState: state.ConfigState{
			LocalCfg: state.LocalCfg{Id: "mobile-client"},
		},
		RouterState: &state.RouterState{},
	})

	assert.NotContains(t, routes.IncludedRoutes, "0.0.0.0/0")
	assert.False(t, routes.IPv6Enabled)
}

func TestBuildTunnelRoutes_WithExitNodeIncludesDefaultAndExcludes(t *testing.T) {
	routes := BuildTunnelRoutes(&core.Nylon{
		ConfigState: state.ConfigState{
			LocalCfg: state.LocalCfg{
				Id:         "mobile-client",
				ExitNode:   "exit-gateway",
				ExcludeIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
			},
			CentralCfg: state.CentralCfg{
				Routers: []state.RouterCfg{
					{
						NodeCfg: state.NodeCfg{Id: "exit-gateway"},
						Endpoints: []*state.DynamicEndpoint{
							state.NewDynamicEndpoint("203.0.113.10:57175"),
							state.NewDynamicEndpoint("[2001:db8::107]:57175"),
						},
					},
				},
			},
		},
		RouterState: &state.RouterState{},
	})

	assert.True(t, prefixListContainsAddr(routes.IncludedRoutes, netip.MustParseAddr("8.8.8.8")))
	assert.Contains(t, routes.ExcludedRoutes, "203.0.113.10/32")
	assert.Contains(t, routes.ExcludedRoutes, "100.64.0.0/10")
	assert.Contains(t, routes.ExcludedRoutes, "169.254.0.0/16")
	assert.Contains(t, routes.ExcludedRoutes, "192.168.0.0/16")
	assert.Contains(t, routes.ExcludedRoutes, "224.0.0.0/4")
	assert.NotContains(t, routes.ExcludedRoutes, "2001:db8::107/128")
	assert.Equal(t, "exit-gateway", routes.ExitNode)
	assert.False(t, routes.IPv6Enabled)
}

func prefixListContainsAddr(prefixes []string, addr netip.Addr) bool {
	for _, raw := range prefixes {
		prefix := netip.MustParsePrefix(raw)
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
