package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/device"
)

func perfFragment(id uint64, total, offset int, chunk []byte) []byte {
	p := make([]byte, nylonFragmentHeaderLen+len(chunk))
	p[0] = nylonFragmentVersion
	binary.BigEndian.PutUint64(p[1:9], id)
	binary.BigEndian.PutUint16(p[9:11], uint16(total))
	binary.BigEndian.PutUint16(p[11:13], uint16(offset))
	copy(p[13:], chunk)
	return p
}
func perfNylon() *Nylon {
	return &Nylon{fragReassembly: make(map[nylonFragmentKey]*nylonFragmentBuffer)}
}

func TestFragmentReassemblyOrderOverlapAndDuplicates(t *testing.T) {
	original := make([]byte, 1400)
	for i := range original {
		original[i] = byte(i * 37)
	}
	cases := [][][2]int{{{0, 1000}, {1000, 1400}}, {{1000, 1400}, {0, 1000}}, {{0, 1000}, {0, 1000}, {800, 1400}}, {{0, 64}, {64, 128}, {65, 129}, {128, 1399}, {1399, 1400}}}
	for c, ranges := range cases {
		n := perfNylon()
		var peer device.NoisePublicKey
		for i, r := range ranges {
			data, complete, err := n.acceptFragment(peer, perfFragment(1, len(original), r[0], original[r[0]:r[1]]))
			if err != nil {
				t.Fatal(err)
			}
			if i == len(ranges)-1 {
				if !complete || !bytes.Equal(original, data) {
					t.Fatalf("case %d invalid reassembly", c)
				}
			} else if complete {
				t.Fatalf("case %d completed early", c)
			}
		}
		if len(n.fragReassembly) != 0 {
			t.Fatal("completed packet retained")
		}
	}
}
func TestFragmentPeerIsolationExpiryAndOwnership(t *testing.T) {
	n := perfNylon()
	var a, b device.NoisePublicKey
	b[0] = 1
	first := perfFragment(7, 128, 0, bytes.Repeat([]byte{1}, 64))
	last := perfFragment(7, 128, 64, bytes.Repeat([]byte{2}, 64))
	n.acceptFragment(a, first)
	n.acceptFragment(b, last)
	if len(n.fragReassembly) != 2 {
		t.Fatal("peer keys collide")
	}
	got, ok, err := n.acceptFragment(a, last)
	if err != nil || !ok {
		t.Fatal("peer A incomplete", err)
	}
	saved := append([]byte(nil), got...)
	n.acceptFragment(a, first)
	n.acceptFragment(a, perfFragment(7, 128, 64, bytes.Repeat([]byte{9}, 64)))
	if !bytes.Equal(got, saved) {
		t.Fatal("returned buffer ownership violated")
	}
	n.fragReassembly[nylonFragmentKey{peer: b, id: 7}].expires = time.Now().Add(-time.Second)
	_, ok, err = n.acceptFragment(b, first)
	if err != nil || ok {
		t.Fatal("expired packet reused", err)
	}
	n.gcFragments(time.Now().Add(time.Minute))
	if len(n.fragReassembly) != 0 {
		t.Fatal("GC retained expired entries")
	}
}
func TestFragmentMalformedAndLengthChange(t *testing.T) {
	var p device.NoisePublicKey
	n := perfNylon()
	bad := [][]byte{nil, make([]byte, 13), perfFragment(1, 0, 0, []byte{1}), perfFragment(1, 10, 9, []byte{1, 2}), perfFragment(1, 10, 0, []byte{1})}
	bad[len(bad)-1][0] = 99
	for _, data := range bad {
		if _, _, err := n.acceptFragment(p, data); err == nil {
			t.Fatal("accepted malformed fragment")
		}
	}
	n.acceptFragment(p, perfFragment(1, 20, 0, []byte{1}))
	if _, _, err := n.acceptFragment(p, perfFragment(1, 21, 1, []byte{2})); err == nil {
		t.Fatal("accepted length change")
	}
	if len(n.fragReassembly) != 0 {
		t.Fatal("length mismatch state retained")
	}
}
func TestFragmentRandomOrderAndConcurrentGC(t *testing.T) {
	n := perfNylon()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(worker)))
			var p device.NoisePublicKey
			p[0] = byte(worker)
			for k := 0; k < 100; k++ {
				data := make([]byte, 1400)
				r.Read(data)
				chunks := [][2]int{{0, 511}, {511, 1023}, {1023, 1400}}
				r.Shuffle(len(chunks), func(i, j int) { chunks[i], chunks[j] = chunks[j], chunks[i] })
				for i, c := range chunks {
					got, ok, err := n.acceptFragment(p, perfFragment(uint64(k), 1400, c[0], data[c[0]:c[1]]))
					if err != nil || (i == 2 && (!ok || !bytes.Equal(got, data))) {
						t.Errorf("concurrent mismatch: %v", err)
						return
					}
				}
			}
		}(worker)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			n.gcFragments(time.Now())
		}
	}()
	wg.Wait()
	if len(n.fragReassembly) != 0 {
		t.Fatal("completed concurrent state retained")
	}
}
func BenchmarkFragmentReassemblyPending(b *testing.B) {
	for _, pending := range []int{0, 128, 1024, 8192} {
		b.Run(fmt.Sprintf("pending_%d", pending), func(b *testing.B) {
			n := perfNylon()
			var p device.NoisePublicKey
			full := bytes.Repeat([]byte{42}, 1400)
			for i := 0; i < pending; i++ {
				n.acceptFragment(p, perfFragment(uint64(1<<63)+uint64(i), 1400, 0, full[:1000]))
			}
			first := perfFragment(0, 1400, 0, full[:1000])
			last := perfFragment(0, 1400, 1000, full[1000:])
			b.SetBytes(1400)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				binary.BigEndian.PutUint64(first[1:9], uint64(i))
				binary.BigEndian.PutUint64(last[1:9], uint64(i))
				n.acceptFragment(p, first)
				data, ok, err := n.acceptFragment(p, last)
				if err != nil || !ok || len(data) != 1400 {
					b.Fatal("reassembly failed", err)
				}
			}
		})
	}
}

func TestFragmentCoverageAllBitBoundaries(t *testing.T) {
	data := make([]byte, 257)
	for i := range data {
		data[i] = byte(i * 7)
	}
	var peer device.NoisePublicKey
	for start := 0; start < 128; start++ {
		for length := 1; length <= 129; length++ {
			n := perfNylon()
			end := start + length
			if _, ok, err := n.acceptFragment(peer, perfFragment(1, len(data), start, data[start:end])); err != nil || ok {
				t.Fatal("middle fragment", start, length, err)
			}
			if start > 0 {
				if _, ok, err := n.acceptFragment(peer, perfFragment(1, len(data), 0, data[:start])); err != nil || ok {
					t.Fatal("prefix fragment", start, length, err)
				}
			}
			got, ok, err := n.acceptFragment(peer, perfFragment(1, len(data), end, data[end:]))
			if err != nil || !ok || !bytes.Equal(got, data) {
				t.Fatal("bitmap boundary mismatch", start, length, err)
			}
		}
	}
}
func TestFragmentOverlapPreservesLastWriteSemantics(t *testing.T) {
	n := perfNylon()
	var peer device.NoisePublicKey
	n.acceptFragment(peer, perfFragment(1, 1400, 0, bytes.Repeat([]byte{1}, 1000)))
	n.acceptFragment(peer, perfFragment(1, 1400, 400, bytes.Repeat([]byte{9}, 200)))
	got, ok, err := n.acceptFragment(peer, perfFragment(1, 1400, 1000, bytes.Repeat([]byte{2}, 400)))
	want := append(bytes.Repeat([]byte{1}, 1000), bytes.Repeat([]byte{2}, 400)...)
	copy(want[400:600], bytes.Repeat([]byte{9}, 200))
	if err != nil || !ok || !bytes.Equal(got, want) {
		t.Fatal("overlap semantics changed", err)
	}
}
