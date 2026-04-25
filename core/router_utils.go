package core

import (
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

func NeighContainsFunc(s *state.RouterState, f func(neigh state.NodeId, route state.NeighRoute) bool) bool {
	for _, n := range s.Neighbours {
		for _, r := range n.Routes {
			if f(n.Id, r) {
				return true
			}
		}
	}
	return false
}

func (r *NylonRouter) ForwardEntryToNode(node state.NodeId) (RouteTableEntry, bool) {
	if node == r.Id {
		return RouteTableEntry{Nh: r.Id}, true
	}

	var best state.SelRoute
	found := false
	for _, route := range r.Routes {
		if route.NodeId != node || route.Nh == r.Id || route.Metric == state.INF {
			continue
		}
		if !found || route.Metric < best.Metric {
			best = route
			found = true
		}
	}
	if !found {
		return RouteTableEntry{}, false
	}

	n := Get[*Nylon](r.State)
	peer := n.Device.LookupPeer(device.NoisePublicKey(r.GetNode(best.Nh).PubKey))
	if peer == nil {
		return RouteTableEntry{}, false
	}
	return RouteTableEntry{
		Nh:   best.Nh,
		Peer: peer,
	}, true
}
