package device

import (
	"errors"
	"github.com/encodeous/nylon/polyamide/tun"
	"testing"
)

type recordingReprocessTUN struct {
	tun.Device
	writes [][][]byte
}

func (t *recordingReprocessTUN) Write(bufs [][]byte, offset int) (int, error) {
	batch := make([][]byte, len(bufs))
	for i, b := range bufs {
		batch[i] = append([]byte(nil), b[offset:]...)
	}
	t.writes = append(t.writes, batch)
	return len(bufs), nil
}
func TestTCReprocessPreservesBatchAndBufferOwnership(t *testing.T) {
	d := &Device{Log: NewLogger(LogLevelSilent, "")}
	d.PopulatePools()
	sink := &recordingReprocessTUN{}
	d.tun.device = sink
	d.InstallFilter(func(_ *Device, e *TCElement) (TCAction, error) {
		if e.GetIPVersion() == 4 || e.GetIPVersion() == 6 {
			return TcBounce, nil
		}
		return TcDrop, nil
	})
	d.InstallFilter(func(_ *Device, e *TCElement) (TCAction, error) {
		if e.GetIPVersion() != 10 {
			return TcPass, nil
		}
		version := int(e.Payload()[0])
		length := 20
		if version == 6 {
			length = 40
		}
		e.InitPacket(version, uint16(length))
		return TcReprocess, nil
	})
	state := NewTCState()
	for round := 0; round < 3; round++ {
		batch := make([]*TCElement, 3)
		for i := range batch {
			batch[i] = d.NewTCElement()
			batch[i].InitPacket(10, 4)
			batch[i].Payload()[0] = 4
			if i == 1 {
				batch[i].Payload()[0] = 6
			}
		}
		d.TCBatch(batch, state)
		if len(sink.writes) != round+1 || len(sink.writes[round]) != 3 {
			t.Fatal("decapsulation broke batching")
		}
		for _, e := range batch {
			if e != nil {
				t.Fatal("element ownership not transferred")
			}
		}
		if len(state.bouncePkts) != 0 || len(state.bounceBufs) != 0 {
			t.Fatal("state not reusable")
		}
		if sink.writes[round][0][0]>>4 != 4 || sink.writes[round][1][0]>>4 != 6 {
			t.Fatal("inner packet corrupted")
		}
	}
}
func TestTCReprocessBoundsAndErrors(t *testing.T) {
	d := &Device{Log: NewLogger(LogLevelSilent, "")}
	calls := 0
	e := &TCElement{Buffer: new([MaxMessageSize]byte)}
	e.InitPacket(10, 4)
	d.InstallFilter(func(_ *Device, _ *TCElement) (TCAction, error) { calls++; return TcReprocess, nil })
	if d.applyTCFilters(e) != TcDrop || calls != maxTCReprocess+1 {
		t.Fatal("unbounded decapsulation", calls)
	}
	d.TCFilters = []TCFilter{func(_ *Device, _ *TCElement) (TCAction, error) { return TcReprocess, errors.New("bad fragment") }}
	if d.applyTCFilters(e) != TcDrop {
		t.Fatal("ignored filter error")
	}
	for _, length := range []int{1, 2, 4, 19, 39} {
		e.InitPacket(10, 4)
		d.TCFilters = []TCFilter{func(_ *Device, e *TCElement) (TCAction, error) {
			e.InitPacket(6, uint16(length))
			return TcReprocess, nil
		}}
		if d.applyTCFilters(e) != TcDrop {
			t.Fatal("accepted truncated inner packet", length)
		}
	}
	e.InitPacket(10, 4)
	d.TCFilters = []TCFilter{func(_ *Device, e *TCElement) (TCAction, error) {
		e.InitPacket(4, 20)
		e.SetLength(65535)
		return TcReprocess, nil
	}}
	if d.applyTCFilters(e) != TcDrop {
		t.Fatal("accepted oversized inner length")
	}
}
