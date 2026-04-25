package mobile

import (
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func TestBuildTunnelRoutes_NoExitNodeOmitsDefault(t *testing.T) {
	routes := BuildTunnelRoutes(&state.State{
		Env: &state.Env{
			LocalCfg: state.LocalCfg{Id: "ios-phone"},
		},
		Modules: map[string]state.NyModule{},
	})

	assert.NotContains(t, routes.IncludedRoutes, "0.0.0.0/0")
	assert.False(t, routes.IPv6Enabled)
}

func TestBuildTunnelRoutes_WithExitNodeIncludesDefaultAndExcludes(t *testing.T) {
	routes := BuildTunnelRoutes(&state.State{
		Env: &state.Env{
			LocalCfg: state.LocalCfg{
				Id:         "ios-phone",
				ExitNode:   "sz-iepl",
				ExcludeIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
			},
			CentralCfg: state.CentralCfg{
				Routers: []state.RouterCfg{
					{
						NodeCfg: state.NodeCfg{Id: "sz-iepl"},
						Endpoints: []*state.DynamicEndpoint{
							state.NewDynamicEndpoint("39.108.107.3:57175"),
							state.NewDynamicEndpoint("[2401:b60:b:2:300::107]:57175"),
						},
					},
				},
			},
		},
		Modules: map[string]state.NyModule{},
	})

	assert.Contains(t, routes.IncludedRoutes, "0.0.0.0/0")
	assert.Contains(t, routes.ExcludedRoutes, "39.108.107.3/32")
	assert.Contains(t, routes.ExcludedRoutes, "100.64.0.0/10")
	assert.Contains(t, routes.ExcludedRoutes, "192.168.0.0/16")
	assert.NotContains(t, routes.ExcludedRoutes, "2401:b60:b:2:300::107/128")
	assert.Equal(t, "sz-iepl", routes.ExitNode)
	assert.False(t, routes.IPv6Enabled)
}
