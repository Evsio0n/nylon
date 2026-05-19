package core

import (
	"bufio"
	"cmp"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

func (n *Nylon) initWireGuard() error {
	dev, tdev, itfName, err := NewWireGuardDevice(n)
	if err != nil {
		return err
	}

	err = dev.Up()
	if err != nil {
		return err
	}

	n.Device = dev
	n.Tun = tdev
	n.Interface = itfName

	fwmark := n.Fwmark
	if fwmark == 0 {
		fwmark = uint32(n.Port)
	}
	n.fwmark = fwmark

	n.InstallTC()
	n.Log.Info("installed nylon traffic control filter for polysock")

	dev.IpcHandler["get=nylon\n"] = func(writer *bufio.ReadWriter) error {
		return HandleNylonIPC(n, writer)
	}

	err = dev.IpcSet(
		fmt.Sprintf(
			`private_key=%s
listen_port=%d
fwmark=%d
`,
			hex.EncodeToString(n.Key[:]),
			n.Port,
			fwmark,
		),
	)
	if err != nil {
		return fmt.Errorf("failed to configure wg device: %v", err)
	}

	err = n.SyncWireGuard()
	if err != nil {
		return err
	}

	for _, cmd := range n.PreUp {
		err = ExecSplit(n.Log, cmd)
		if err != nil {
			n.Log.Error("failed to run pre-up command", "err", err)
		}
	}

	if !n.NoNetConfigure {
		for _, addr := range n.GetRouter(n.LocalCfg.Id).Addresses {
			err := ConfigureAlias(n.Log, itfName, addr)
			if err != nil {
				n.Log.Error("failed to configure alias", "err", err)
			} else if !slices.Contains(n.AppliedSystem.Aliases, addr) {
				n.AppliedSystem.Aliases = append(n.AppliedSystem.Aliases, addr)
			}
		}

		err = InitInterface(n.Log, itfName, fwmark)
		if err != nil {
			return err
		}

		if n.AdvertiseExitNode {
			err = SetupExitNode(n.Log, itfName, n.GetPrefixes())
			if err != nil {
				n.Log.Error("failed to setup exit node", "err", err)
			}
		}
	}

	for _, cmd := range n.PostUp {
		err = ExecSplit(n.Log, cmd)
		if err != nil {
			n.Log.Error("failed to run post-up command", "err", err)
		}
	}

	n.RepeatTask(func() error {
		return n.UpdateWireGuard()
	}, n.ProbeDelay)

	return nil
}

func (n *Nylon) cleanupWireGuard() error {
	for _, route := range n.AppliedSystem.Routes {
		err := RemoveRoute(n.Log, n.Tun, n.Interface, route, n.fwmark)
		if err != nil {
			n.Log.Error("failed to remove route", "err", err)
		}
	}
	for _, addr := range n.AppliedSystem.Aliases {
		err := RemoveAlias(n.Log, n.Interface, addr)
		if err != nil {
			n.Log.Error("failed to remove alias", "err", err)
		}
	}
	if !n.NoNetConfigure {
		if n.AdvertiseExitNode {
			CleanupExitNode(n.Log, n.Interface, n.GetPrefixes())
		}
		CleanupInterface(n.Log, n.Interface, n.fwmark)
	}

	for _, cmd := range n.PreDown {
		err := ExecSplit(n.Log, cmd)
		if err != nil {
			n.Log.Error("failed to run pre-down command", "err", err)
		}
	}
	err := CleanupWireGuardDevice(n)
	if err != nil {
		return err
	}
	for _, cmd := range n.PostDown {
		err = ExecSplit(n.Log, cmd)
		if err != nil {
			n.Log.Error("failed to run post-down command", "err", err)
		}
	}
	return nil
}

func (n *Nylon) SyncWireGuard() error {
	if n.Device == nil {
		return nil
	}
	if n.AppliedSystem.Peers == nil {
		n.AppliedSystem.Peers = make(map[state.NodeId]state.NyPublicKey)
	}

	desired := make(map[state.NodeId]state.NyPublicKey)
	for _, peer := range n.GetPeers(n.LocalCfg.Id) {
		ncfg := n.GetNode(peer)
		desired[peer] = ncfg.PubKey
	}

	for peer, oldKey := range n.AppliedSystem.Peers {
		newKey, ok := desired[peer]
		if !ok || newKey != oldKey {
			n.Log.Debug("removing", "peer", peer)
			n.Device.RemovePeer(device.NoisePublicKey(oldKey))
			delete(n.AppliedSystem.Peers, peer)
		}
	}

	for _, peer := range slices.Sorted(slices.Values(n.GetPeers(n.LocalCfg.Id))) {
		ncfg := n.GetNode(peer)
		wgPeer := n.Device.LookupPeer(device.NoisePublicKey(ncfg.PubKey))
		if wgPeer == nil {
			n.Log.Debug("adding", "peer", peer)
			var err error
			wgPeer, err = n.Device.NewPeer(device.NoisePublicKey(ncfg.PubKey))
			if err != nil {
				return err
			}
			wgPeer.Start()
		}
		if n.IsClient(peer) {
			wgPeer.SetPreferRoaming(true)
		}
		n.AppliedSystem.Peers[peer] = ncfg.PubKey
	}

	return n.syncWireGuardEndpoints()
}

func (n *Nylon) UpdateWireGuard() error {
	if n.Device == nil {
		return nil
	}
	if err := n.syncWireGuardEndpoints(); err != nil {
		return err
	}
	return n.SyncSystemState()
}

func (n *Nylon) syncWireGuardEndpoints() error {
	if n.Device == nil {
		return nil
	}
	dev := n.Device

	for _, peer := range slices.Sorted(slices.Values(n.GetPeers(n.LocalCfg.Id))) {
		if n.IsClient(peer) {
			continue
		}
		pcfg := n.GetRouter(peer)
		nhNeigh := n.RouterState.GetNeighbour(peer)
		eps := make([]conn.Endpoint, 0)

		if nhNeigh != nil {
			links := slices.Clone(nhNeigh.Eps)
			slices.SortStableFunc(links, func(a, b state.Endpoint) int {
				return cmp.Compare(a.Metric(), b.Metric())
			})
			for _, ep := range links {
				ap, err := ep.AsNylonEndpoint().DynEP.Get()
				if err != nil || !endpointIsLocallyRoutable(ap) {
					continue
				}
				nep, err := ep.AsNylonEndpoint().GetWgEndpoint(n.Device)
				if err != nil {
					continue
				}
				eps = append(eps, nep)
			}
		}

		for _, ep := range pcfg.Endpoints {
			ap, err := ep.Get()
			if err != nil {
				continue
			}
			if !endpointIsLocallyRoutable(ap) {
				continue
			}
			if !slices.ContainsFunc(eps, func(endpoint conn.Endpoint) bool {
				return endpoint.DstIPPort() == ap
			}) {
				endpoint, err := n.Device.Bind().ParseEndpoint(ap.String())
				if err != nil {
					return fmt.Errorf("peer %s: invalid endpoint %q: %w", peer, ap.String(), err)
				}
				eps = append(eps, endpoint)
			}
		}

		wgPeer := dev.LookupPeer(device.NoisePublicKey(pcfg.PubKey))
		if wgPeer != nil {
			wgPeer.SetEndpoints(eps)
		}
	}

	return nil
}

func (n *Nylon) SyncSystemState() error {
	if n.NoNetConfigure {
		return nil
	}
	if err := n.syncAliases(); err != nil {
		return err
	}
	return n.syncSystemRoutes()
}

func (n *Nylon) syncAliases() error {
	desired := n.GetRouter(n.LocalCfg.Id).Addresses
	for _, newEntry := range desired {
		if !slices.Contains(n.AppliedSystem.Aliases, newEntry) {
			n.Log.Debug("installing alias", "addr", newEntry.String())
			err := ConfigureAlias(n.Log, n.Interface, newEntry)
			if err != nil {
				n.Log.Error("failed to configure alias", "err", err)
			}
		}
	}
	for _, oldEntry := range n.AppliedSystem.Aliases {
		if !slices.Contains(desired, oldEntry) {
			n.Log.Debug("removing old alias", "addr", oldEntry.String())
			err := RemoveAlias(n.Log, n.Interface, oldEntry)
			if err != nil {
				n.Log.Error("failed to remove alias", "err", err)
			}
		}
	}
	if len(n.AppliedSystem.Aliases) != 0 && len(desired) == 0 && runtime.GOOS == "linux" {
		n.AppliedSystem.Routes = nil
	}
	n.AppliedSystem.Aliases = slices.Clone(desired)
	return nil
}

func (n *Nylon) syncSystemRoutes() error {
	newEntries := n.ComputeSysRouteTable()
	oldEntries := n.AppliedSystem.Routes
	for _, oldEntry := range oldEntries {
		if !slices.Contains(newEntries, oldEntry) {
			n.Log.Debug("removing old route", "prefix", oldEntry.String())
			err := RemoveRoute(n.Log, n.Tun, n.Interface, oldEntry, n.fwmark)
			if err != nil {
				n.Log.Error("failed to remove route", "err", err)
			}
		}
	}
	for _, newEntry := range newEntries {
		if !slices.Contains(oldEntries, newEntry) {
			n.Log.Debug("installing new route", "prefix", newEntry.String())
			err := ConfigureRoute(n.Log, n.Tun, n.Interface, newEntry, n.fwmark)
			if err != nil {
				n.Log.Error("failed to configure route", "err", err)
			}
		}
	}
	n.AppliedSystem.Routes = slices.Clone(newEntries)
	return nil
}

func endpointIsLocallyRoutable(ap netip.AddrPort) bool {
	if !ap.Addr().Is6() {
		return true
	}
	conn, err := net.DialTimeout("udp6", ap.String(), 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
