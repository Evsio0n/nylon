package mobile

import (
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/core"
	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func TestCollectTopologyMarksRemoteDefaultRouteAdvertiserAsExit(t *testing.T) {
	n := &core.Nylon{
		ConfigState: state.ConfigState{
			LocalCfg: state.LocalCfg{Id: "mobile-client"},
			CentralCfg: state.CentralCfg{
				Routers: []state.RouterCfg{
					{NodeCfg: state.NodeCfg{Id: "relay-node"}},
					{NodeCfg: state.NodeCfg{Id: "exit-gateway"}},
				},
				Clients: []state.ClientCfg{
					{NodeCfg: state.NodeCfg{Id: "mobile-client"}},
				},
				Graph: []string{
					"mobile-client, relay-node",
					"relay-node, exit-gateway",
				},
			},
		},
		RouterState: &state.RouterState{
			Advertised: map[netip.Prefix]state.Advertisement{},
		},
	}

	topology := collectTopology(n, []routeInfo{
		{
			Prefix:   "0.0.0.0/0",
			NextHop:  "relay-node",
			RouterID: "exit-gateway",
			Metric:   128,
		},
	})

	assert.True(t, topologyNodeByID(topology.Nodes, "exit-gateway").IsExitNode)
	assert.False(t, topologyNodeByID(topology.Nodes, "relay-node").IsExitNode)
	assert.Len(t, topology.Edges, 2)
}

func topologyNodeByID(nodes []topologyNode, id string) topologyNode {
	for _, node := range nodes {
		if node.ID == id {
			return node
		}
	}
	return topologyNode{}
}
