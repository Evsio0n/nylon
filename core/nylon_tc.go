package core

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"google.golang.org/protobuf/proto"
)

const (
	NyProtoId          = 8
	NyExitProtoId      = 9
	exitPacketHopLimit = 64
)

// polyamide traffic control for nylon

func (n *Nylon) InstallTC(s *state.State) {
	r := Get[*NylonRouter](s)
	t := Get[*NylonTrace](s)

	if state.DBG_trace_tc {
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			if packet.Validate() { // make sure it's an IP packet
				peer := packet.FromPeer
				if peer == nil {
					peer = packet.ToPeer
				}
				src := packet.GetSrc()
				dst := packet.GetDst()
				if src.IsValid() &&
					dst.IsValid() &&
					peer != nil &&
					src != netip.IPv4Unspecified() && src != netip.IPv6Unspecified() &&
					dst != netip.IPv4Unspecified() && dst != netip.IPv6Unspecified() {
					t.Submit(fmt.Sprintf("Unhandled TC packet: %v -> %v, peer %s\n", packet.GetSrc(), packet.GetDst(), peer))
				}
			}
			return device.TcPass, nil
		})
	}

	if s.LocalCfg.ExitNode != "" {
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			if packet.Incoming() || !packet.Validate() || (packet.GetIPVersion() != 4 && packet.GetIPVersion() != 6) {
				return device.TcPass, nil
			}
			entry, ok := r.ForwardTable.Lookup(packet.GetDst())
			if ok {
				return device.TcPass, nil // overlay routes keep normal routing semantics.
			}
			entry, ok = r.ForwardEntryToNode(s.LocalCfg.ExitNode)
			if !ok || entry.Peer == nil {
				if state.DBG_trace_tc {
					t.Submit(fmt.Sprintf("ExitDrop: %v -> %v, exit %s, reason no_route\n", packet.GetSrc(), packet.GetDst(), s.LocalCfg.ExitNode))
				}
				return device.TcDrop, nil
			}
			src, dst := packet.GetSrc(), packet.GetDst()
			if err := n.wrapExitPacket(packet, s.LocalCfg.ExitNode, s.Id); err != nil {
				if state.DBG_trace_tc {
					t.Submit(fmt.Sprintf("ExitDrop: %v -> %v, exit %s, reason %v\n", src, dst, s.LocalCfg.ExitNode, err))
				}
				return device.TcDrop, nil
			}
			packet.ToPeer = entry.Peer
			packet.Priority = device.TcMediumPriority
			if state.DBG_trace_tc {
				t.Submit(fmt.Sprintf("ExitEncap: %v -> %v, exit %s via %s\n", src, dst, s.LocalCfg.ExitNode, entry.Nh))
			}
			return device.TcForward, nil
		})
	}

	// bounce back packets if using system routing
	if n.env.UseSystemRouting {
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			if packet.Incoming() {
				// bounce incoming packets
				//dev.Log.Verbosef("BounceFwd packet: %v -> %v", packet.GetSrc(), packet.GetDst())
				return device.TcBounce, nil
			}
			return device.TcPass, nil
		})
		// forward only outgoing packets based on the routing table
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			entry, ok := r.ForwardTable.Lookup(packet.GetDst())
			if ok && !packet.Incoming() {
				packet.ToPeer = entry.Peer
				if state.DBG_trace_tc {
					t.Submit(fmt.Sprintf("Fwd packet: %v -> %v, via %s\n", packet.GetSrc(), packet.GetDst(), entry.Nh))
				}
				return device.TcForward, nil
			}
			return device.TcPass, nil
		})
	} else {
		// forward packets based on the routing table
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			entry, ok := r.ForwardTable.Lookup(packet.GetDst())
			if ok {
				packet.ToPeer = entry.Peer
				if state.DBG_trace_tc {
					t.Submit(fmt.Sprintf("Fwd packet: %v -> %v, via %s\n", packet.GetSrc(), packet.GetDst(), entry.Nh))
				}
				return device.TcForward, nil
			}
			return device.TcPass, nil
		})

		// handle TTL
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			if packet.Incoming() && (packet.GetIPVersion() == 4 || packet.GetIPVersion() == 6) {
				// allow traceroute to figure out the route
				ttl := packet.GetTTL()
				if ttl >= 1 {
					ttl--
					packet.DecrementTTL()
				}
				if ttl == 0 {
					if state.DBG_trace_tc {
						t.Submit(fmt.Sprintf("TTL Expired: %v -> %v\n", packet.GetSrc(), packet.GetDst()))
					}
					return device.TcBounce, nil
				}
			}
			return device.TcPass, nil
		})
	}

	// handle passive client traffic separately

	// bounce back packets destined for the current node
	n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
		entry, ok := r.ExitTable.Lookup(packet.GetDst())
		// we should only accept packets destined to us, but not our passive clients
		if ok && entry.Nh == s.Id {
			if state.DBG_trace_tc {
				t.Submit(fmt.Sprintf("Exit: %v -> %v\n", packet.GetSrc(), packet.GetDst()))
			}
			//dev.Log.Verbosef("BounceCur packet: %v -> %v", packet.GetSrc(), packet.GetDst())
			return device.TcBounce, nil
		}
		//dev.Log.Verbosef("pass packet: %v -> %v, %v", packet.GetSrc(), packet.GetDst(), entry.Nh)
		return device.TcPass, nil
	})

	// handle incoming nylon packets
	n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
		if packet.Incoming() && packet.GetIPVersion() == NyProtoId {
			n.handleNylonPacket(packet.Payload(), packet.FromEp, packet.FromPeer)
			return device.TcDrop, nil
		}
		return device.TcPass, nil
	})

	// handle explicit exit packets after installing all normal IP filters; TC
	// runs filters in reverse installation order, so this executes first.
	n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
		if !packet.Incoming() || packet.GetIPVersion() != NyExitProtoId {
			return device.TcPass, nil
		}
		action, err := n.handleExitPacket(s, packet)
		if err != nil && state.DBG_trace_tc {
			t.Submit(fmt.Sprintf("ExitDrop: reason %v\n", err))
		}
		return action, err
	})
}

func (n *Nylon) SendNylon(pkt *protocol.Ny, endpoint conn.Endpoint, peer *device.Peer) error {
	return n.SendNylonBundle(&protocol.TransportBundle{Packets: []*protocol.Ny{pkt}}, endpoint, peer)
}

func (n *Nylon) wrapExitPacket(packet *device.TCElement, exitNode, originNode state.NodeId) error {
	exit := []byte(exitNode)
	origin := []byte(originNode)
	if len(exit) > 255 || len(origin) > 255 {
		return errors.New("node id too long")
	}

	origLen := len(packet.Packet)
	headerLen := device.PolyHeaderSize + 3 + len(exit) + len(origin)
	totalLen := headerLen + origLen
	if totalLen > len(packet.Buffer)-device.MessageTransportHeaderSize {
		return errors.New("packet too large for exit encapsulation")
	}

	buf := packet.Buffer[device.MessageTransportHeaderSize : device.MessageTransportHeaderSize+totalLen]
	copy(buf[headerLen:], packet.Packet)
	packet.Packet = buf
	packet.SetIPVersion(NyExitProtoId)
	packet.SetLength(uint16(totalLen))
	payload := packet.Payload()
	payload[0] = exitPacketHopLimit
	payload[1] = byte(len(exit))
	payload[2] = byte(len(origin))
	copy(payload[3:], exit)
	copy(payload[3+len(exit):], origin)
	return nil
}

type exitPacket struct {
	hopLimit uint8
	exit     state.NodeId
	origin   state.NodeId
	inner    []byte
}

func parseExitPacket(packet *device.TCElement) (exitPacket, error) {
	payload := packet.Payload()
	if len(payload) < 3 {
		return exitPacket{}, errors.New("malformed exit packet")
	}
	exitLen := int(payload[1])
	originLen := int(payload[2])
	headerLen := 3 + exitLen + originLen
	if len(payload) <= headerLen {
		return exitPacket{}, errors.New("exit packet missing inner packet")
	}
	return exitPacket{
		hopLimit: payload[0],
		exit:     state.NodeId(string(payload[3 : 3+exitLen])),
		origin:   state.NodeId(string(payload[3+exitLen : headerLen])),
		inner:    payload[headerLen:],
	}, nil
}

func (n *Nylon) handleExitPacket(s *state.State, packet *device.TCElement) (device.TCAction, error) {
	r := Get[*NylonRouter](s)
	t := Get[*NylonTrace](s)
	ep, err := parseExitPacket(packet)
	if err != nil {
		return device.TcDrop, err
	}
	if ep.hopLimit == 0 {
		return device.TcDrop, errors.New("exit packet hop limit exceeded")
	}

	if ep.exit != s.Id {
		entry, ok := r.ForwardEntryToNode(ep.exit)
		if !ok || entry.Peer == nil {
			return device.TcDrop, fmt.Errorf("no route to exit node %s", ep.exit)
		}
		packet.Payload()[0]--
		packet.ToPeer = entry.Peer
		packet.Priority = device.TcMediumPriority
		if state.DBG_trace_tc {
			t.Submit(fmt.Sprintf("ExitTransit: origin %s exit %s via %s\n", ep.origin, ep.exit, entry.Nh))
		}
		return device.TcForward, nil
	}

	if !s.LocalCfg.AdvertiseExitNode {
		return device.TcDrop, errors.New("local node is not advertising exit service")
	}
	src, err := packetSrc(ep.inner)
	if err != nil {
		return device.TcDrop, err
	}
	if !nodeOwnsAddr(&s.CentralCfg, ep.origin, src) {
		return device.TcDrop, fmt.Errorf("source %s is not owned by origin node %s", src, ep.origin)
	}
	dst, err := packetDst(ep.inner)
	if err != nil {
		return device.TcDrop, err
	}
	if state.DBG_trace_tc {
		t.Submit(fmt.Sprintf("ExitDecap: origin %s %s -> %s\n", ep.origin, src, dst))
	}
	copy(packet.Packet[:len(ep.inner)], ep.inner)
	packet.Packet = packet.Packet[:len(ep.inner)]
	packet.ParsePacket()
	return device.TcBounce, nil
}

func packetSrc(packet []byte) (netip.Addr, error) {
	return packetAddr(packet, true)
}

func packetDst(packet []byte) (netip.Addr, error) {
	return packetAddr(packet, false)
}

func packetAddr(packet []byte, src bool) (netip.Addr, error) {
	if len(packet) == 0 {
		return netip.Addr{}, errors.New("empty inner packet")
	}
	switch packet[0] >> 4 {
	case 4:
		offset := device.IPv4offsetDst
		if src {
			offset = device.IPv4offsetSrc
		}
		if len(packet) < offset+net.IPv4len {
			return netip.Addr{}, errors.New("short IPv4 packet")
		}
		return netip.AddrFrom4([4]byte(packet[offset : offset+net.IPv4len])), nil
	case 6:
		offset := device.IPv6offsetDst
		if src {
			offset = device.IPv6offsetSrc
		}
		if len(packet) < offset+net.IPv6len {
			return netip.Addr{}, errors.New("short IPv6 packet")
		}
		return netip.AddrFrom16([16]byte(packet[offset : offset+net.IPv6len])), nil
	default:
		return netip.Addr{}, errors.New("inner packet is not IP")
	}
}

func nodeOwnsAddr(cfg *state.CentralCfg, node state.NodeId, addr netip.Addr) bool {
	n := cfg.TryGetNode(node)
	if n == nil {
		return false
	}
	for _, prefix := range n.Prefixes {
		if prefix.GetPrefix().Contains(addr) {
			return true
		}
	}
	for _, nodeAddr := range n.Addresses {
		if nodeAddr == addr {
			return true
		}
	}
	if cfg.IsRouter(node) {
		for _, peer := range cfg.GetPeers(node) {
			if !cfg.IsClient(peer) {
				continue
			}
			client := cfg.GetClient(peer)
			for _, prefix := range client.Prefixes {
				if prefix.GetPrefix().Contains(addr) {
					return true
				}
			}
			for _, nodeAddr := range client.Addresses {
				if nodeAddr == addr {
					return true
				}
			}
		}
	}
	return false
}

func (n *Nylon) SendNylonBundle(pkt *protocol.TransportBundle, endpoint conn.Endpoint, peer *device.Peer) error {
	tce := n.Device.NewTCElement()
	offset := device.MessageTransportOffsetContent + device.PolyHeaderSize
	buf, err := proto.MarshalOptions{
		Deterministic: true,
	}.MarshalAppend(tce.Buffer[offset:offset], pkt)
	if err != nil {
		n.Device.PutMessageBuffer(tce.Buffer)
		n.Device.PutTCElement(tce)
		return err
	}
	tce.InitPacket(NyProtoId, uint16(len(buf)+device.PolyHeaderSize))
	tce.Priority = device.TcHighPriority

	tce.ToEp = endpoint
	tce.ToPeer = peer

	// TODO: Optimize? is it worth it?

	tcs := device.NewTCState()

	n.Device.TCBatch([]*device.TCElement{tce}, tcs)
	return nil
}

func (n *Nylon) handleNylonPacket(packet []byte, endpoint conn.Endpoint, peer *device.Peer) {
	bundle := &protocol.TransportBundle{}
	err := proto.Unmarshal(packet, bundle)
	if err != nil {
		// log skipped message
		n.env.Log.Debug("Failed to unmarshal packet", "err", err)
		return
	}

	e := n.env

	neigh := e.FindNodeBy(state.NyPublicKey(peer.GetPublicKey()))
	if neigh == nil {
		// this should not be possible
		panic("impossible state, peer added, but not a node in the network")
		return
	}

	defer func() {
		err := recover()
		if err != nil {
			n.env.Log.Error("panic while handling poly socket: %v", err)
		}
	}()

	for _, pkt := range bundle.Packets {
		switch pkt.Type.(type) {
		case *protocol.Ny_SeqnoRequestOp:
			e.Dispatch(func(s *state.State) error {
				return routerHandleSeqnoRequest(s, *neigh, pkt.GetSeqnoRequestOp())
			})
		case *protocol.Ny_RouteOp:
			e.Dispatch(func(s *state.State) error {
				return routerHandleRouteUpdate(s, *neigh, pkt.GetRouteOp())
			})
		case *protocol.Ny_AckRetractOp:
			e.Dispatch(func(s *state.State) error {
				return routerHandleAckRetract(s, *neigh, pkt.GetAckRetractOp())
			})
		case *protocol.Ny_ProbeOp:
			handleProbe(n, pkt.GetProbeOp(), endpoint, peer, *neigh)
		}
	}
}
