package core

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/encodeous/nylon/state"
	"golang.org/x/net/websocket"
)

//go:embed ui
var uiFS embed.FS

const (
	defaultControlPlaneAddr = "127.0.0.1:58175"
	apiV1Prefix             = "/api/v1"
)

// ControlPlane is a NyModule that exposes a REST API + WebSocket
// for inspecting and managing nylon mesh state.
type ControlPlane struct {
	env        *state.Env
	server     *http.Server
	meshServer *http.Server
	trace      *NylonTrace
	wsClients  wsClientSet
}

// wsClientSet tracks active WebSocket connections for clean shutdown.
type wsClientSet struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]struct{}
}

func (cs *wsClientSet) add(c *websocket.Conn) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.clients[c] = struct{}{}
}

func (cs *wsClientSet) remove(c *websocket.Conn) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.clients, c)
}

func (cs *wsClientSet) closeAll() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for c := range cs.clients {
		c.Close()
	}
	cs.clients = make(map[*websocket.Conn]struct{})
}

// --- JSON response types ---

type NodeInfo struct {
	Id        string   `json:"id"`
	IsRouter  bool     `json:"is_router"`
	Addresses []string `json:"addresses,omitempty"`
	PublicKey string   `json:"public_key"`
}

type RouteInfo struct {
	Prefix    string `json:"prefix"`
	NextHop   string `json:"next_hop"`
	RouterId  string `json:"router_id"`
	Seqno     uint16 `json:"seqno"`
	Metric    uint32 `json:"metric"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type NeighbourInfo struct {
	Id         string         `json:"id"`
	BestMetric uint32         `json:"best_metric"`
	Endpoints  []EndpointInfo `json:"endpoints"`
	Routes     []string       `json:"routes"`
}

type EndpointInfo struct {
	Address  string `json:"address"`
	Resolved string `json:"resolved,omitempty"`
	Active   bool   `json:"active"`
	Metric   uint32 `json:"metric"`
	IsRemote bool   `json:"is_remote"`
}

type PrefixInfo struct {
	Prefix    string `json:"prefix"`
	RouterId  string `json:"router_id"`
	Metric    uint32 `json:"metric"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Type      string `json:"type"`
}

type ForwardEntry struct {
	Prefix  string `json:"prefix"`
	NextHop string `json:"next_hop"`
}

type StatusResponse struct {
	NodeId    string `json:"node_id"`
	IsRouter  bool   `json:"is_router"`
	StartedAt string `json:"started_at"`
}

// WSEvent is the envelope for WebSocket messages sent to clients.
type WSEvent struct {
	Type string          `json:"type"` // "trace", "state_change", "error"
	Data json.RawMessage `json:"data"`
}

// WSCommand is the envelope for WebSocket messages received from clients.
type WSCommand struct {
	Type string          `json:"type"` // "subscribe", "ping"
	Data json.RawMessage `json:"data,omitempty"`
}

// WriteOperationRequest is the body for POST write endpoints.
type WriteOperationRequest struct {
	// Reload triggers a config reload (re-read central.yaml and restart)
	Reload bool `json:"reload,omitempty"`
}

// APIResponse is a generic response envelope.
type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// --- ControlPlane NyModule implementation ---

func (cp *ControlPlane) Init(s *state.State) error {
	cp.env = s.Env
	cp.wsClients = wsClientSet{clients: make(map[*websocket.Conn]struct{})}

	addr := defaultControlPlaneAddr
	// future: allow override via LocalCfg or AuxConfig

	mux := http.NewServeMux()
	// Phase 1: read-only endpoints
	mux.HandleFunc("GET "+apiV1Prefix+"/status", cp.handleStatus)
	mux.HandleFunc("GET "+apiV1Prefix+"/nodes", cp.handleNodes)
	mux.HandleFunc("GET "+apiV1Prefix+"/routes", cp.handleRoutes)
	mux.HandleFunc("GET "+apiV1Prefix+"/neighbours", cp.handleNeighbours)
	mux.HandleFunc("GET "+apiV1Prefix+"/prefixes", cp.handlePrefixes)
	mux.HandleFunc("GET "+apiV1Prefix+"/forward", cp.handleForward)
	mux.HandleFunc("GET "+apiV1Prefix+"/sysroutes", cp.handleSysRoutes)

	// Phase 2: write endpoints
	mux.HandleFunc("POST "+apiV1Prefix+"/reload", cp.handleReload)
	mux.HandleFunc("POST "+apiV1Prefix+"/flush_routes", cp.handleFlushRoutes)

	// Phase 2: WebSocket
	mux.Handle(apiV1Prefix+"/ws", websocket.Handler(cp.handleWebSocket))

	// Phase 3: Topology aggregation (queries neighbours over mesh)
	mux.HandleFunc("GET "+apiV1Prefix+"/topology", cp.handleTopology)

	// Phase 3: Embedded Web UI (SPA)
	uiSub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		s.Log.Warn("control plane: failed to create UI subtree", "error", err)
	} else {
		fileServer := http.FileServer(http.FS(uiSub))
		mux.Handle("/ui/", http.StripPrefix("/ui/", fileServer))
		// Root redirect to /ui/
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/", http.StatusFound)
		})
	}

	handler := mux

	// Listen on localhost
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.Log.Warn("control plane failed to bind, skipping", "addr", addr, "error", err)
		return nil // non-fatal: control plane is optional
	}

	cp.server = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		s.Log.Info("control plane listening", "addr", addr)
		if err := cp.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.Log.Error("control plane server error", "error", err)
		}
	}()

	// Also listen on mesh interface IP so other nodes can query our API
	meshListener := cp.listenMesh(s, handler)
	cp.meshServer = meshListener

	return nil
}

func (cp *ControlPlane) Cleanup(s *state.State) error {
	// Close all WebSocket clients first
	cp.wsClients.closeAll()

	if cp.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return cp.server.Shutdown(ctx)
	}
	return nil
}

// --- Phase 1: Read-only API handlers ---

func (cp *ControlPlane) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := StatusResponse{
		NodeId:   string(cp.env.LocalCfg.Id),
		IsRouter: cp.env.IsRouter(cp.env.LocalCfg.Id),
	}
	writeJSON(w, resp)
}

func (cp *ControlPlane) handleNodes(w http.ResponseWriter, r *http.Request) {
	nodes := make([]NodeInfo, 0)
	for _, n := range cp.env.Routers {
		nodes = append(nodes, nodeCfgToInfo(n.NodeCfg, true))
	}
	for _, n := range cp.env.Clients {
		nodes = append(nodes, nodeCfgToInfo(n.NodeCfg, false))
	}
	writeJSON(w, nodes)
}

func (cp *ControlPlane) handleRoutes(w http.ResponseWriter, r *http.Request) {
	result := make(chan []RouteInfo, 1)
	cp.env.Dispatch(func(s *state.State) error {
		routes := make([]RouteInfo, 0, len(s.Routes))
		for prefix, route := range s.Routes {
			ri := RouteInfo{
				Prefix:   prefix.String(),
				NextHop:  string(route.Nh),
				RouterId: string(route.NodeId),
				Seqno:    route.Seqno,
				Metric:   route.Metric,
			}
			if !route.ExpireAt.IsZero() {
				ri.ExpiresAt = route.ExpireAt.Format(time.RFC3339)
			}
			routes = append(routes, ri)
		}
		slices.SortFunc(routes, func(a, b RouteInfo) int {
			return strings.Compare(a.Prefix, b.Prefix)
		})
		result <- routes
		return nil
	})

	select {
	case routes := <-result:
		writeJSON(w, routes)
	case <-time.After(5 * time.Second):
		writeError(w, http.StatusServiceUnavailable, "dispatch timeout")
	}
}

func (cp *ControlPlane) handleNeighbours(w http.ResponseWriter, r *http.Request) {
	result := make(chan []NeighbourInfo, 1)
	cp.env.Dispatch(func(s *state.State) error {
		neighbours := make([]NeighbourInfo, 0, len(s.Neighbours))
		for _, n := range s.Neighbours {
			ni := NeighbourInfo{
				Id: string(n.Id),
			}
			best := n.BestEndpoint()
			if best != nil {
				ni.BestMetric = best.Metric()
			}
			for _, ep := range n.Eps {
				nep := ep.AsNylonEndpoint()
				ei := EndpointInfo{
					Active:   nep.IsActive(),
					Metric:   nep.Metric(),
					IsRemote: nep.IsRemote(),
				}
				ei.Address = nep.DynEP.String()
				ap, err := nep.DynEP.Get()
				if err == nil {
					ei.Resolved = ap.String()
				}
				ni.Endpoints = append(ni.Endpoints, ei)
			}
			routes := make([]string, 0, len(n.Routes))
			for prefix := range n.Routes {
				routes = append(routes, prefix.String())
			}
			slices.Sort(routes)
			ni.Routes = routes
			neighbours = append(neighbours, ni)
		}
		slices.SortFunc(neighbours, func(a, b NeighbourInfo) int {
			return strings.Compare(a.Id, b.Id)
		})
		result <- neighbours
		return nil
	})

	select {
	case neighbours := <-result:
		writeJSON(w, neighbours)
	case <-time.After(5 * time.Second):
		writeError(w, http.StatusServiceUnavailable, "dispatch timeout")
	}
}

func (cp *ControlPlane) handlePrefixes(w http.ResponseWriter, r *http.Request) {
	result := make(chan []PrefixInfo, 1)
	cp.env.Dispatch(func(s *state.State) error {
		prefixes := make([]PrefixInfo, 0, len(s.Advertised))
		for prefix, adv := range s.Advertised {
			pi := PrefixInfo{
				Prefix:   prefix.String(),
				RouterId: string(adv.NodeId),
				Metric:   adv.MetricFn(),
			}
			if !adv.Expiry.IsZero() {
				timeRem := time.Until(adv.Expiry)
				if timeRem > 24*time.Hour {
					pi.ExpiresAt = "never"
				} else {
					pi.ExpiresAt = adv.Expiry.Format(time.RFC3339)
				}
			}
			if adv.IsPassiveHold {
				pi.Type = "passive"
			} else {
				pi.Type = "active"
			}
			prefixes = append(prefixes, pi)
		}
		slices.SortFunc(prefixes, func(a, b PrefixInfo) int {
			return strings.Compare(a.Prefix, b.Prefix)
		})
		result <- prefixes
		return nil
	})

	select {
	case prefixes := <-result:
		writeJSON(w, prefixes)
	case <-time.After(5 * time.Second):
		writeError(w, http.StatusServiceUnavailable, "dispatch timeout")
	}
}

func (cp *ControlPlane) handleForward(w http.ResponseWriter, r *http.Request) {
	result := make(chan []ForwardEntry, 1)
	cp.env.Dispatch(func(s *state.State) error {
		router := Get[*NylonRouter](s)
		entries := make([]ForwardEntry, 0)
		for prefix, entry := range router.ForwardTable.All() {
			entries = append(entries, ForwardEntry{
				Prefix:  prefix.String(),
				NextHop: string(entry.Nh),
			})
		}
		slices.SortFunc(entries, func(a, b ForwardEntry) int {
			return strings.Compare(a.Prefix, b.Prefix)
		})
		result <- entries
		return nil
	})

	select {
	case entries := <-result:
		writeJSON(w, entries)
	case <-time.After(5 * time.Second):
		writeError(w, http.StatusServiceUnavailable, "dispatch timeout")
	}
}

func (cp *ControlPlane) handleSysRoutes(w http.ResponseWriter, r *http.Request) {
	result := make(chan []string, 1)
	cp.env.Dispatch(func(s *state.State) error {
		router := Get[*NylonRouter](s)
		sysRoutes := router.ComputeSysRouteTable()
		routes := make([]string, 0, len(sysRoutes))
		for _, p := range sysRoutes {
			routes = append(routes, p.String())
		}
		slices.Sort(routes)
		result <- routes
		return nil
	})

	select {
	case routes := <-result:
		writeJSON(w, routes)
	case <-time.After(5 * time.Second):
		writeError(w, http.StatusServiceUnavailable, "dispatch timeout")
	}
}

// --- Phase 2: Write operation handlers ---

// handleReload triggers a config reload by setting Updating and cancelling the context.
// The Bootstrap loop in entrypoint.go will re-read configs and restart.
func (cp *ControlPlane) handleReload(w http.ResponseWriter, r *http.Request) {
	if cp.env.Stopping.Load() {
		writeError(w, http.StatusConflict, "node is shutting down")
		return
	}
	if !cp.env.Updating.CompareAndSwap(false, true) {
		writeError(w, http.StatusConflict, "reload already in progress")
		return
	}

	cp.env.Log.Info("control plane: config reload triggered via API")
	cp.env.Cancel(fmt.Errorf("config reload triggered via control plane API"))

	writeJSON(w, APIResponse{
		Success: true,
		Message: "reload initiated, node will restart with updated config",
	})
}

// handleFlushRoutes triggers a full route table update to all neighbours.
func (cp *ControlPlane) handleFlushRoutes(w http.ResponseWriter, r *http.Request) {
	if cp.env.Stopping.Load() {
		writeError(w, http.StatusConflict, "node is shutting down")
		return
	}

	result := make(chan string, 1)
	cp.env.Dispatch(func(s *state.State) error {
		router := Get[*NylonRouter](s)
		FullTableUpdate(s.RouterState, router)
		neighCount := len(router.IO)
		result <- fmt.Sprintf("flushed full route table to %d neighbours", neighCount)
		return nil
	})

	select {
	case msg := <-result:
		writeJSON(w, APIResponse{
			Success: true,
			Message: msg,
		})
	case <-time.After(5 * time.Second):
		writeError(w, http.StatusServiceUnavailable, "dispatch timeout")
	}
}

// --- Phase 2: WebSocket handler ---

func (cp *ControlPlane) handleWebSocket(ws *websocket.Conn) {
	// Resolve NylonTrace at first use (module may init after ControlPlane)
	if cp.trace == nil {
		cp.env.Dispatch(func(s *state.State) error {
			cp.trace = Get[*NylonTrace](s)
			return nil
		})
	}

	cp.wsClients.add(ws)
	defer func() {
		cp.wsClients.remove(ws)
		ws.Close()
	}()

	// Subscribe to trace events
	traceCh := make(chan interface{}, 64)
	if cp.trace != nil {
		cp.trace.Register(traceCh)
		defer cp.trace.Unregister(traceCh)
	}

	// Read loop: handle incoming commands from client
	readCh := make(chan WSCommand, 16)
	go func() {
		defer close(readCh)
		for {
			var cmd WSCommand
			err := websocket.JSON.Receive(ws, &cmd)
			if err != nil {
				return // connection closed or error
			}
			readCh <- cmd
		}
	}()

	// Main event loop: forward trace events and handle commands
	for {
		select {
		case msg, ok := <-traceCh:
			if !ok {
				return
			}
			data, err := json.Marshal(map[string]interface{}{
				"message": fmt.Sprintf("%v", msg),
				"ts":      time.Now().Format(time.RFC3339Nano),
			})
			if err != nil {
				continue
			}
			event := WSEvent{
				Type: "trace",
				Data: data,
			}
			if err := websocket.JSON.Send(ws, event); err != nil {
				return // client disconnected
			}

		case cmd, ok := <-readCh:
			if !ok {
				return // read loop ended (client disconnected)
			}
			cp.handleWSCommand(ws, cmd)

		case <-cp.env.Context.Done():
			// Server shutting down
			return
		}
	}
}

// handleWSCommand processes commands received from WebSocket clients.
func (cp *ControlPlane) handleWSCommand(ws *websocket.Conn, cmd WSCommand) {
	switch cmd.Type {
	case "ping":
		pong, _ := json.Marshal(map[string]string{"pong": time.Now().Format(time.RFC3339Nano)})
		websocket.JSON.Send(ws, WSEvent{Type: "pong", Data: pong})
	default:
		errData, _ := json.Marshal(map[string]string{"error": "unknown command: " + cmd.Type})
		websocket.JSON.Send(ws, WSEvent{Type: "error", Data: errData})
	}
}

// --- helpers ---

func nodeCfgToInfo(n state.NodeCfg, isRouter bool) NodeInfo {
	addrs := make([]string, 0, len(n.Addresses))
	for _, a := range n.Addresses {
		addrs = append(addrs, a.String())
	}
	return NodeInfo{
		Id:        string(n.Id),
		IsRouter:  isRouter,
		Addresses: addrs,
		PublicKey: base64.StdEncoding.EncodeToString(n.PubKey[:]),
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("control plane: failed to encode JSON", "error", err)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error": msg,
		"code":  fmt.Sprintf("%d", code),
	})
}

// --- Mesh listener ---

// listenMesh binds the control plane HTTP server on the node's first mesh prefix address
// so other nylon nodes can query the API through the mesh tunnel.
func (cp *ControlPlane) listenMesh(s *state.State, handler http.Handler) *http.Server {
	// Find this node's mesh address from its prefix
	node := s.Env.TryGetNode(s.Env.LocalCfg.Id)
	if node == nil {
		return nil
	}

	var meshAddr string
	for _, pfx := range node.Prefixes {
		addr := pfx.GetPrefix().Addr()
		if addr.IsValid() {
			meshAddr = netip.AddrPortFrom(addr, defaultControlPlanePort).String()
			break
		}
	}
	if meshAddr == "" {
		return nil
	}

	ln, err := net.Listen("tcp", meshAddr)
	if err != nil {
		s.Log.Warn("control plane: mesh listener failed to bind", "addr", meshAddr, "error", err)
		return nil
	}

	srv := &http.Server{
		Addr:              meshAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		s.Log.Info("control plane mesh listener started", "addr", meshAddr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.Log.Error("control plane mesh listener error", "error", err)
		}
	}()

	return srv
}

// --- Topology aggregation ---

const (
	defaultControlPlanePort = 58175
	topologyQueryTimeout   = 5 * time.Second
)

// neighbourTopology is the JSON shape we fetch from each neighbour's /api/v1/status + /api/v1/neighbours.
type neighbourTopology struct {
	NodeID     string `json:"node_id"`
	IsRouter   bool   `json:"is_router"`
	Neighbours []struct {
		ID         string `json:"id"`
		BestMetric int    `json:"best_metric"`
	} `json:"neighbours"`
}

// handleTopology aggregates topology from the entire mesh by querying each reachable node's API.
// Algorithm:
//  1. Start with our own neighbours (from dispatch)
//  2. For each known node, query its /api/v1/status + /api/v1/neighbours via mesh network
//  3. Build a complete graph of all nodes and edges
func (cp *ControlPlane) handleTopology(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), topologyQueryTimeout)
	defer cancel()

	type topoNode struct {
		ID       string `json:"id"`
		IsRouter bool   `json:"is_router"`
		IsSelf   bool   `json:"is_self"`
	}
	type topoEdge struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Metric int    `json:"metric"`
	}

	visited := make(map[string]bool)
	var allEdges []topoEdge
	nodeMap := make(map[string]topoNode)

	myID := string(cp.env.LocalCfg.Id)

	// Add self
	nodeMap[myID] = topoNode{ID: myID, IsRouter: cp.env.IsRouter(state.NodeId(myID)), IsSelf: true}

	// Get our own neighbours via dispatch
	type ownNeigh struct {
		Id         string
		BestMetric int
	}
	neighResult := make(chan []ownNeigh, 1)
	cp.env.Dispatch(func(s *state.State) error {
		var list []ownNeigh
		for _, n := range s.Neighbours {
			on := ownNeigh{Id: string(n.Id)}
			best := n.BestEndpoint()
			if best != nil {
				on.BestMetric = int(best.Metric())
			}
			list = append(list, on)
		}
		neighResult <- list
		return nil
	})

	var ownNeighs []ownNeigh
	select {
	case ownNeighs = <-neighResult:
	case <-time.After(3 * time.Second):
		writeError(w, http.StatusServiceUnavailable, "dispatch timeout")
		return
	}

	for _, nb := range ownNeighs {
		edgeKey := myID + "-" + nb.Id
		if !visited[edgeKey] {
			visited[edgeKey] = true
			allEdges = append(allEdges, topoEdge{From: myID, To: nb.Id, Metric: nb.BestMetric})
		}
		nodeMap[nb.Id] = topoNode{ID: nb.Id, IsRouter: cp.env.IsRouter(state.NodeId(nb.Id))}
	}

	// Query each known node's API via mesh network for their neighbour view
	type pendingNode struct {
		id   string
		addr string
	}

	var queue []pendingNode
	for _, nb := range ownNeighs {
		addr := cp.resolveNodeAddr(nb.Id)
		if addr != "" {
			queue = append(queue, pendingNode{id: nb.Id, addr: addr})
		}
	}

	queried := make(map[string]bool)
	queried[myID] = true

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if queried[item.id] {
			continue
		}
		queried[item.id] = true

		topo := cp.queryNodeTopology(ctx, item.addr)
		if topo == nil {
			continue
		}

		// Update node info from remote
		nodeMap[item.id] = topoNode{ID: topo.NodeID, IsRouter: topo.IsRouter}

		for _, nb := range topo.Neighbours {
			edgeA := item.id + "-" + nb.ID
			edgeB := nb.ID + "-" + item.id
			if !visited[edgeA] && !visited[edgeB] {
				visited[edgeA] = true
				allEdges = append(allEdges, topoEdge{From: item.id, To: nb.ID, Metric: nb.BestMetric})
			}

			if _, exists := nodeMap[nb.ID]; !exists {
				nodeMap[nb.ID] = topoNode{ID: nb.ID, IsRouter: cp.env.IsRouter(state.NodeId(nb.ID))}
			}

			if !queried[nb.ID] {
				addr := cp.resolveNodeAddr(nb.ID)
				if addr != "" {
					queue = append(queue, pendingNode{id: nb.ID, addr: addr})
				}
			}
		}
	}

	// Build result
	var allNodes []topoNode
	for _, n := range nodeMap {
		allNodes = append(allNodes, n)
	}

	writeJSON(w, map[string]interface{}{
		"nodes": allNodes,
		"edges": allEdges,
	})
}

// queryNodeTopology fetches /api/v1/status + /api/v1/neighbours from a remote node via mesh.
func (cp *ControlPlane) queryNodeTopology(ctx context.Context, addr string) *neighbourTopology {
	client := &http.Client{Timeout: topologyQueryTimeout}

	// Fetch status
	statusResp, err := client.Get("http://" + addr + apiV1Prefix + "/status")
	if err != nil {
		return nil
	}
	defer statusResp.Body.Close()

	var status struct {
		NodeID   string `json:"node_id"`
		IsRouter bool   `json:"is_router"`
	}
	if err := json.NewDecoder(statusResp.Body).Decode(&status); err != nil {
		return nil
	}

	// Fetch neighbours
	neighResp, err := client.Get("http://" + addr + apiV1Prefix + "/neighbours")
	if err != nil {
		return nil
	}
	defer neighResp.Body.Close()

	var neighs []struct {
		ID         string `json:"id"`
		BestMetric int    `json:"best_metric"`
	}
	if err := json.NewDecoder(neighResp.Body).Decode(&neighs); err != nil {
		return nil
	}

	return &neighbourTopology{
		NodeID:     status.NodeID,
		IsRouter:   status.IsRouter,
		Neighbours: neighs,
	}
}

// resolveNodeAddr returns the mesh IP:port for a given node ID.
func (cp *ControlPlane) resolveNodeAddr(nodeId string) string {
	node := cp.env.TryGetNode(state.NodeId(nodeId))
	if node == nil {
		return ""
	}
	for _, pfx := range node.Prefixes {
		addr := pfx.GetPrefix().Addr()
		if addr.IsValid() {
			return netip.AddrPortFrom(addr, defaultControlPlanePort).String()
		}
	}
	return ""
}
