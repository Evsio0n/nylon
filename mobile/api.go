package mobile

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/encodeous/nylon/core"
	"github.com/encodeous/nylon/state"
)

type statusResponse struct {
	NodeID     string `json:"node_id"`
	IsRouter   bool   `json:"is_router"`
	IsExitNode bool   `json:"is_exit_node"`
	StartedAt  string `json:"started_at,omitempty"`
}

type nodeInfo struct {
	ID         string   `json:"id"`
	IsRouter   bool     `json:"is_router"`
	IsExitNode bool     `json:"is_exit_node"`
	Addresses  []string `json:"addresses,omitempty"`
	PublicKey  string   `json:"public_key"`
}

type routeInfo struct {
	Prefix    string `json:"prefix"`
	NextHop   string `json:"next_hop"`
	RouterID  string `json:"router_id"`
	Seqno     uint16 `json:"seqno"`
	Metric    uint32 `json:"metric"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type neighbourInfo struct {
	ID         string         `json:"id"`
	BestMetric uint32         `json:"best_metric"`
	Endpoints  []endpointInfo `json:"endpoints"`
	Routes     []string       `json:"routes"`
}

type endpointInfo struct {
	Address  string `json:"address"`
	Resolved string `json:"resolved,omitempty"`
	Active   bool   `json:"active"`
	Metric   uint32 `json:"metric"`
	IsRemote bool   `json:"is_remote"`
}

type topologyResponse struct {
	Nodes []topologyNode `json:"nodes"`
	Edges []topologyEdge `json:"edges"`
}

type topologyNode struct {
	ID         string `json:"id"`
	IsRouter   bool   `json:"is_router"`
	IsExitNode bool   `json:"is_exit_node"`
	IsSelf     bool   `json:"is_self"`
}

type topologyEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Metric uint32 `json:"metric"`
}

// GetStatus returns JSON of the node status directly from the in-process engine.
func (n *NylonMobile) GetStatus() string {
	engine := n.engine()
	if engine == nil {
		return marshalError("not running")
	}
	return marshalJSON(statusResponse{
		NodeID:     string(engine.LocalCfg.Id),
		IsRouter:   engine.IsRouter(engine.LocalCfg.Id),
		IsExitNode: engine.LocalCfg.AdvertiseExitNode,
	})
}

// GetNodes returns JSON of all known mesh nodes.
func (n *NylonMobile) GetNodes() string {
	engine := n.engine()
	if engine == nil {
		return marshalJSON([]nodeInfo{})
	}

	exitNodes := exitNodeSet(engine)
	nodes := make([]nodeInfo, 0, len(engine.Routers)+len(engine.Clients))
	for _, router := range engine.Routers {
		nodes = append(nodes, nodeCfgToMobileInfo(router.NodeCfg, true, exitNodes))
	}
	for _, client := range engine.Clients {
		nodes = append(nodes, nodeCfgToMobileInfo(client.NodeCfg, false, exitNodes))
	}
	slices.SortFunc(nodes, func(a, b nodeInfo) int {
		return strings.Compare(a.ID, b.ID)
	})
	return marshalJSON(nodes)
}

// GetNeighbours returns JSON of direct neighbours with endpoint metrics.
func (n *NylonMobile) GetNeighbours() string {
	engine := n.engine()
	if engine == nil {
		return marshalJSON([]neighbourInfo{})
	}

	result, ok := dispatchSnapshot(engine, collectNeighbours)
	if !ok {
		return marshalError("timed out waiting for dispatch")
	}
	return marshalJSON(result)
}

// GetRoutes returns JSON of the selected Babel route table.
func (n *NylonMobile) GetRoutes() string {
	engine := n.engine()
	if engine == nil {
		return marshalJSON([]routeInfo{})
	}

	result, ok := dispatchSnapshot(engine, collectRoutes)
	if !ok {
		return marshalError("timed out waiting for dispatch")
	}
	return marshalJSON(result)
}

// GetTopology returns JSON topology directly from local config/routing state.
func (n *NylonMobile) GetTopology() string {
	engine := n.engine()
	if engine == nil {
		return marshalJSON(topologyResponse{})
	}

	routes, ok := dispatchSnapshot(engine, collectRoutes)
	if !ok {
		routes = nil
	}
	return marshalJSON(collectTopology(engine, routes))
}

func (n *NylonMobile) engine() *core.Nylon {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.nylon
}

func dispatchSnapshot[T any](engine *core.Nylon, collect func(*core.Nylon) T) (T, bool) {
	result := make(chan T, 1)
	engine.Dispatch(func() error {
		result <- collect(engine)
		return nil
	})

	select {
	case v := <-result:
		return v, true
	case <-engine.Context.Done():
		var zero T
		return zero, false
	case <-time.After(5 * time.Second):
		var zero T
		return zero, false
	}
}

func collectRoutes(engine *core.Nylon) []routeInfo {
	routes := make([]routeInfo, 0, len(engine.RouterState.Routes))
	for prefix, route := range engine.RouterState.Routes {
		ri := routeInfo{
			Prefix:   prefix.String(),
			NextHop:  string(route.Nh),
			RouterID: string(route.NodeId),
			Seqno:    route.Seqno,
			Metric:   route.Metric,
		}
		if !route.ExpireAt.IsZero() {
			ri.ExpiresAt = route.ExpireAt.Format(time.RFC3339)
		}
		routes = append(routes, ri)
	}
	slices.SortFunc(routes, func(a, b routeInfo) int {
		if c := strings.Compare(a.Prefix, b.Prefix); c != 0 {
			return c
		}
		return strings.Compare(a.RouterID, b.RouterID)
	})
	return routes
}

func collectNeighbours(engine *core.Nylon) []neighbourInfo {
	neighbours := make([]neighbourInfo, 0, len(engine.RouterState.Neighbours))
	for _, neigh := range engine.RouterState.Neighbours {
		ni := neighbourInfo{ID: string(neigh.Id)}
		if best := neigh.BestEndpoint(); best != nil {
			ni.BestMetric = best.Metric()
		}
		for _, ep := range neigh.Eps {
			nep := ep.AsNylonEndpoint()
			ei := endpointInfo{
				Address:  nep.DynEP.String(),
				Active:   nep.IsActive(),
				Metric:   nep.Metric(),
				IsRemote: nep.IsRemote(),
			}
			if ap, err := nep.DynEP.Get(); err == nil {
				ei.Resolved = ap.String()
			}
			ni.Endpoints = append(ni.Endpoints, ei)
		}
		for prefix := range neigh.Routes {
			ni.Routes = append(ni.Routes, prefix.String())
		}
		slices.Sort(ni.Routes)
		neighbours = append(neighbours, ni)
	}
	slices.SortFunc(neighbours, func(a, b neighbourInfo) int {
		return strings.Compare(a.ID, b.ID)
	})
	return neighbours
}

func collectTopology(engine *core.Nylon, routes []routeInfo) topologyResponse {
	exitNodes := exitNodeSet(engine)
	for _, route := range routes {
		if route.Metric < state.INF && isDefaultRoute(route.Prefix) {
			exitNodes[route.RouterID] = true
		}
	}

	nodeMap := make(map[string]topologyNode)
	for _, router := range engine.Routers {
		id := string(router.Id)
		nodeMap[id] = topologyNode{
			ID:         id,
			IsRouter:   true,
			IsExitNode: exitNodes[id],
			IsSelf:     router.Id == engine.LocalCfg.Id,
		}
	}
	for _, client := range engine.Clients {
		id := string(client.Id)
		nodeMap[id] = topologyNode{
			ID:         id,
			IsRouter:   false,
			IsExitNode: exitNodes[id],
			IsSelf:     client.Id == engine.LocalCfg.Id,
		}
	}
	if _, ok := nodeMap[string(engine.LocalCfg.Id)]; !ok {
		nodeMap[string(engine.LocalCfg.Id)] = topologyNode{
			ID:         string(engine.LocalCfg.Id),
			IsRouter:   engine.IsRouter(engine.LocalCfg.Id),
			IsExitNode: engine.LocalCfg.AdvertiseExitNode,
			IsSelf:     true,
		}
	}

	edges := make([]topologyEdge, 0)
	allNodes := make([]string, 0, len(engine.Routers)+len(engine.Clients))
	for _, node := range engine.CentralCfg.GetNodes() {
		allNodes = append(allNodes, string(node.Id))
	}
	graph, err := state.ParseGraph(engine.CentralCfg.Graph, allNodes)
	if err == nil {
		for _, pair := range graph {
			edges = append(edges, topologyEdge{From: string(pair.V1), To: string(pair.V2)})
		}
	}
	annotateTopologyEdgeMetrics(edges, routes)

	nodes := make([]topologyNode, 0, len(nodeMap))
	for _, node := range nodeMap {
		nodes = append(nodes, node)
	}
	slices.SortFunc(nodes, func(a, b topologyNode) int {
		if a.IsSelf != b.IsSelf {
			if a.IsSelf {
				return -1
			}
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	slices.SortFunc(edges, func(a, b topologyEdge) int {
		if c := strings.Compare(a.From, b.From); c != 0 {
			return c
		}
		return strings.Compare(a.To, b.To)
	})

	return topologyResponse{Nodes: nodes, Edges: edges}
}

func annotateTopologyEdgeMetrics(edges []topologyEdge, routes []routeInfo) {
	best := make(map[string]uint32, len(routes))
	for _, route := range routes {
		if route.Metric >= state.INF {
			continue
		}
		current, ok := best[route.NextHop]
		if !ok || route.Metric < current {
			best[route.NextHop] = route.Metric
		}
	}
	for i := range edges {
		if metric, ok := best[edges[i].To]; ok {
			edges[i].Metric = metric
			continue
		}
		if metric, ok := best[edges[i].From]; ok {
			edges[i].Metric = metric
		}
	}
}

func nodeCfgToMobileInfo(n state.NodeCfg, isRouter bool, exitNodes map[string]bool) nodeInfo {
	addrs := make([]string, 0, len(n.Addresses))
	for _, addr := range n.Addresses {
		addrs = append(addrs, addr.String())
	}
	return nodeInfo{
		ID:         string(n.Id),
		IsRouter:   isRouter,
		IsExitNode: exitNodes[string(n.Id)],
		Addresses:  addrs,
		PublicKey:  base64.StdEncoding.EncodeToString(n.PubKey[:]),
	}
}

func exitNodeSet(engine *core.Nylon) map[string]bool {
	exitNodes := make(map[string]bool)
	if engine.LocalCfg.AdvertiseExitNode {
		exitNodes[string(engine.LocalCfg.Id)] = true
	}
	for _, prefix := range []string{"0.0.0.0/0", "::/0"} {
		if adv, ok := engine.RouterState.Advertised[netip.MustParsePrefix(prefix)]; ok && adv.MetricFn() < state.INF {
			exitNodes[string(adv.NodeId)] = true
		}
	}
	return exitNodes
}

func isDefaultRoute(prefix string) bool {
	return prefix == "0.0.0.0/0" || prefix == "::/0"
}

func marshalJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return marshalError(err.Error())
	}
	return string(data)
}

func marshalError(message string) string {
	data, _ := json.Marshal(map[string]string{"error": message})
	return string(data)
}
