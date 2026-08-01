package core

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/require"
)

func TestMeshListenerReturnsWhenStateIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(context.Canceled)
	s := &state.State{Env: &state.Env{
		Context:  ctx,
		LocalCfg: state.LocalCfg{Id: "node-a"},
		CentralCfg: state.CentralCfg{Routers: []state.RouterCfg{{
			NodeCfg: state.NodeCfg{
				Id: "node-a",
				Prefixes: []state.PrefixHealthWrapper{{PrefixHealth: &state.StaticPrefixHealth{
					Prefix: netip.MustParsePrefix("192.0.2.1/32"),
				}}},
			},
		}}},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}}
	done := make(chan struct{})
	cp := &ControlPlane{}

	go func() {
		defer close(done)
		cp.listenMeshDelayed(s, http.NewServeMux())
	}()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		require.Fail(t, "mesh listener did not stop after cancellation")
	}
}
