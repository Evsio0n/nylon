package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"time"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

const (
	NyFragProtoId              = 10
	nylonFragmentVersion       = 1
	nylonFragmentHeaderLen     = 13
	nylonFragmentReassemblyTTL = 30 * time.Second
)

type nylonFragmentKey struct {
	peer device.NoisePublicKey
	id   uint64
}

type nylonFragmentBuffer struct {
	total    int
	data     []byte
	seen     []uint64
	received int
	expires  time.Time
}

func (n *Nylon) maybeFragmentForward(s *state.State, packet *device.TCElement) (bool, error) {
	fragmentMTU := s.LocalCfg.EffectiveFragmentMTU()
	if fragmentMTU == 0 {
		return false, nil
	}
	maxPacketLen := maxPlaintextForTransportMTU(fragmentMTU, s.LocalCfg.EffectiveMTU())
	if maxPacketLen <= 0 || len(packet.Packet) <= maxPacketLen {
		return false, nil
	}
	if packet.ToPeer == nil {
		return false, errors.New("cannot fragment packet without destination peer")
	}
	if len(s.LocalCfg.FragmentPeers) > 0 {
		nid := s.FindNodeBy(state.NyPublicKey(packet.ToPeer.GetPublicKey()))
		if nid == nil || !slices.Contains(s.LocalCfg.FragmentPeers, *nid) {
			return false, nil
		}
	}
	if packet.GetIPVersion() == NyFragProtoId {
		return false, fmt.Errorf("fragment packet size %d exceeds fragment_mtu %d", len(packet.Packet), fragmentMTU)
	}

	fragments, err := n.fragmentPacket(packet, maxPacketLen)
	if err != nil {
		return false, err
	}
	packet.Fragments = fragments
	return true, nil
}

func (n *Nylon) fragmentPacket(packet *device.TCElement, maxPacketLen int) ([]*device.TCElement, error) {
	maxPayloadLen := maxPacketLen - device.PolyHeaderSize - nylonFragmentHeaderLen
	if maxPayloadLen <= 0 {
		return nil, fmt.Errorf("fragment_mtu leaves no room for fragment payload")
	}
	if len(packet.Packet) > device.MaxContentSize {
		return nil, fmt.Errorf("packet too large to fragment: %d", len(packet.Packet))
	}

	packetID := n.fragSeq.Add(1)
	totalLen := len(packet.Packet)
	fragments := make([]*device.TCElement, 0, (totalLen+maxPayloadLen-1)/maxPayloadLen)
	for offset := 0; offset < totalLen; offset += maxPayloadLen {
		end := offset + maxPayloadLen
		if end > totalLen {
			end = totalLen
		}
		chunk := packet.Packet[offset:end]
		fragLen := device.PolyHeaderSize + nylonFragmentHeaderLen + len(chunk)

		frag := n.Device.NewTCElement()
		frag.InitPacket(NyFragProtoId, uint16(fragLen))
		frag.ToPeer = packet.ToPeer
		frag.ToEp = packet.ToEp
		frag.Priority = packet.Priority

		payload := frag.Payload()
		payload[0] = nylonFragmentVersion
		binary.BigEndian.PutUint64(payload[1:9], packetID)
		binary.BigEndian.PutUint16(payload[9:11], uint16(totalLen))
		binary.BigEndian.PutUint16(payload[11:13], uint16(offset))
		copy(payload[nylonFragmentHeaderLen:], chunk)
		fragments = append(fragments, frag)
	}
	return fragments, nil
}

func (n *Nylon) handleNylonFragment(packet *device.TCElement) bool {
	if packet.FromPeer == nil {
		n.env.Log.Debug("dropping fragment without source peer")
		return false
	}
	reassembled, complete, err := n.acceptFragment(packet.FromPeer.GetPublicKey(), packet.Payload())
	if err != nil {
		n.env.Log.Debug("dropping malformed fragment", "err", err)
		return false
	}
	if !complete {
		return false
	}

	// Reuse the final fragment's buffer and its existing receive batch. A
	// recursive single-packet TCBatch allocates a fresh state and writes to TUN
	// once per completed packet, defeating the receiver's normal batching.
	copy(packet.Buffer[device.MessageTransportHeaderSize:], reassembled)
	packet.Packet = packet.Buffer[device.MessageTransportHeaderSize : device.MessageTransportHeaderSize+len(reassembled)]
	return true
}

func (n *Nylon) acceptFragment(peer device.NoisePublicKey, payload []byte) ([]byte, bool, error) {
	if len(payload) <= nylonFragmentHeaderLen {
		return nil, false, errors.New("fragment payload too short")
	}
	if payload[0] != nylonFragmentVersion {
		return nil, false, fmt.Errorf("unsupported fragment version %d", payload[0])
	}

	packetID := binary.BigEndian.Uint64(payload[1:9])
	totalLen := int(binary.BigEndian.Uint16(payload[9:11]))
	offset := int(binary.BigEndian.Uint16(payload[11:13]))
	chunk := payload[nylonFragmentHeaderLen:]
	if totalLen <= 0 || totalLen > device.MaxContentSize {
		return nil, false, fmt.Errorf("invalid reassembled packet length %d", totalLen)
	}
	if offset < 0 || offset+len(chunk) > totalLen {
		return nil, false, fmt.Errorf("fragment range %d..%d exceeds total %d", offset, offset+len(chunk), totalLen)
	}

	now := time.Now()
	key := nylonFragmentKey{peer: peer, id: packetID}

	n.fragMu.Lock()
	defer n.fragMu.Unlock()

	buf := n.fragReassembly[key]
	// The existing one-second maintenance task expires the whole table. Only
	// inspect this entry on the packet path, preserving the 30-second deadline
	// even when the maintenance task has not run yet.
	if buf != nil && now.After(buf.expires) {
		delete(n.fragReassembly, key)
		buf = nil
	}
	if buf == nil {
		buf = &nylonFragmentBuffer{
			total:   totalLen,
			data:    make([]byte, totalLen),
			seen:    make([]uint64, (totalLen+63)/64),
			expires: now.Add(nylonFragmentReassemblyTTL),
		}
		n.fragReassembly[key] = buf
	} else if buf.total != totalLen {
		delete(n.fragReassembly, key)
		return nil, false, errors.New("fragment total length changed")
	}

	copy(buf.data[offset:], chunk)
	// Track exact byte coverage, including arbitrary overlapping fragments,
	// in 64-byte groups instead of visiting each byte individually.
	end := offset + len(chunk)
	firstWord, lastWord := offset/64, (end-1)/64
	for word := firstWord; word <= lastWord; word++ {
		mask := ^uint64(0)
		if word == firstWord {
			mask <<= uint(offset % 64)
		}
		if word == lastWord {
			mask &= ^uint64(0) >> uint(63-(end-1)%64)
		}
		buf.received += bits.OnesCount64(mask &^ buf.seen[word])
		buf.seen[word] |= mask
	}
	if buf.received != buf.total {
		return nil, false, nil
	}

	delete(n.fragReassembly, key)
	// Removing the entry transfers ownership to the caller; no other fragment
	// can mutate this allocation after the mutex is released.
	return buf.data, true, nil
}

func (n *Nylon) gcFragments(now time.Time) {
	n.fragMu.Lock()
	defer n.fragMu.Unlock()
	n.gcFragmentsLocked(now)
}

func (n *Nylon) gcFragmentsLocked(now time.Time) {
	for k, buf := range n.fragReassembly {
		if now.After(buf.expires) {
			delete(n.fragReassembly, k)
		}
	}
}

func maxPlaintextForTransportMTU(limit, paddingMTU int) int {
	for size := limit; size > 0; size-- {
		if device.MessageTransportSize+size+wireGuardPaddingSize(size, paddingMTU) <= limit {
			return size
		}
	}
	return 0
}

func wireGuardPaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + device.PaddingMultiple - 1) & ^(device.PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + device.PaddingMultiple - 1) & ^(device.PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}
