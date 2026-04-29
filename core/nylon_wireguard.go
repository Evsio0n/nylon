package core

import (
	"bufio"
	"cmp"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

func (n *Nylon) initWireGuard(s *state.State) error {
	dev, tdev, itfName, err := NewWireGuardDevice(s, n)
	if err != nil {
		return err
	}

	err = dev.Up()
	if err != nil {
		return err
	}

	n.Device = dev
	n.Tun = tdev
	n.itfName = itfName

	fwmark := s.Fwmark
	if fwmark == 0 {
		fwmark = uint32(s.Port)
	}
	n.fwmark = fwmark

	n.InstallTC(s)
	s.Log.Info("installed nylon traffic control filter for polysock")

	dev.IpcHandler["get=nylon\n"] = func(writer *bufio.ReadWriter) error {
		return HandleNylonIPCGet(s, writer)
	}

	// TODO: fully convert to code-based api
	err = dev.IpcSet(
		fmt.Sprintf(
			`private_key=%s
listen_port=%d
fwmark=%d
`,
			hex.EncodeToString(s.Key[:]),
			s.Port,
			fwmark,
		),
	)
	if err != nil {
		return fmt.Errorf("failed to configure wg device: %v", err)
	}

	// add peers
	peers := s.GetPeers(s.Id)
	for _, peer := range peers {
		s.Log.Debug("adding", "peer", peer)
		ncfg := s.GetNode(peer)
		wgPeer, err := dev.NewPeer(device.NoisePublicKey(ncfg.PubKey))
		if err != nil {
			return err
		}
		if s.IsClient(peer) {
			wgPeer.SetPreferRoaming(true)
		}

		// seed initial endpoints
		if s.IsClient(peer) {
			wgPeer.Start()
			continue
		}
		rcfg := s.GetRouter(peer)
		endpoints := make([]conn.Endpoint, 0)
		for _, nep := range rcfg.Endpoints {
			ap, err := nep.Get()
			if err != nil {
				continue
			}
			if !endpointIsLocallyRoutable(ap) {
				continue
			}
			endpoint, err := n.Device.Bind().ParseEndpoint(ap.String())
			if err != nil {
				return fmt.Errorf("peer %s: invalid endpoint %q: %w", peer, ap.String(), err)
			}
			endpoints = append(endpoints, endpoint)
		}
		wgPeer.SetEndpoints(endpoints)

		wgPeer.Start()
	}

	// configure system networking

	// run pre-up commands
	for _, cmd := range s.PreUp {
		err = ExecSplit(s.Log, cmd)
		if err != nil {
			s.Log.Error("failed to run pre-up command", "err", err)
		}
	}

	if !s.NoNetConfigure {
		for _, addr := range s.GetRouter(s.Id).Addresses {
			err := ConfigureAlias(s.Log, itfName, addr)
			if err != nil {
				s.Log.Error("failed to configure alias", "err", err)
			}
		}

		err = InitInterface(s.Log, itfName, fwmark)
		if err != nil {
			return err
		}

		if s.LocalCfg.AdvertiseExitNode {
			err = SetupExitNode(s.Log, itfName, s.GetPrefixes())
			if err != nil {
				s.Log.Error("failed to setup exit node", "err", err)
			}
		}
	}

	// run post-up commands
	for _, cmd := range s.PostUp {
		err = ExecSplit(s.Log, cmd)
		if err != nil {
			s.Log.Error("failed to run post-up command", "err", err)
		}
	}

	// init wireguard related tasks
	s.RepeatTask(UpdateWireGuard, state.ProbeDelay)

	return nil
}

func (n *Nylon) cleanupWireGuard(s *state.State) error {
	// remove routes
	for _, route := range n.prevInstalledRoutes {
		err := RemoveRoute(s.Log, n.Tun, n.itfName, route, n.fwmark)
		if err != nil {
			s.Log.Error("failed to remove route", "err", err)
		}
	}
	if !s.NoNetConfigure {
		if s.LocalCfg.AdvertiseExitNode {
			CleanupExitNode(s.Log, n.itfName, s.GetPrefixes())
		}
		CleanupInterface(s.Log, n.itfName, n.fwmark)
	}

	// run pre-down commands
	for _, cmd := range s.PreDown {
		err := ExecSplit(s.Log, cmd)
		if err != nil {
			s.Log.Error("failed to run pre-down command", "err", err)
		}
	}
	err := CleanupWireGuardDevice(s, n)
	if err != nil {
		return err
	}
	// run post-down commands
	for _, cmd := range s.PostDown {
		err = ExecSplit(s.Log, cmd)
		if err != nil {
			s.Log.Error("failed to run post-down command", "err", err)
		}
	}
	return nil
}

func UpdateWireGuard(s *state.State) error {
	n := Get[*Nylon](s)
	dev := n.Device

	// configure endpoints
	for _, peer := range slices.Sorted(slices.Values(s.GetPeers(s.Id))) {
		if s.IsClient(peer) {
			continue
		}
		pcfg := s.GetRouter(peer)
		nhNeigh := s.GetNeighbour(peer)
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

		// add endpoint if it is not in the list
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
		wgPeer.SetEndpoints(eps)
	}

	// configure changed route table entries
	if !s.NoNetConfigure {
		router := Get[*NylonRouter](s)
		newEntries := router.ComputeSysRouteTable()
		oldEntries := n.prevInstalledRoutes
		for _, oldEntry := range oldEntries {
			if !slices.Contains(newEntries, oldEntry) {
				// uninstall route
				s.Log.Debug("removing old route", "prefix", oldEntry.String())
				err := RemoveRoute(s.Log, n.Tun, n.itfName, oldEntry, n.fwmark)
				if err != nil {
					s.Log.Error("failed to remove route", "err", err)
				}
			}
		}
		for _, newEntry := range newEntries {
			if !slices.Contains(oldEntries, newEntry) {
				// install route
				s.Log.Debug("installing new route", "prefix", newEntry.String())
				err := ConfigureRoute(s.Log, n.Tun, n.itfName, newEntry, n.fwmark)
				if err != nil {
					s.Log.Error("failed to configure route", "err", err)
				}
			}
		}
		n.prevInstalledRoutes = newEntries
	}
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
