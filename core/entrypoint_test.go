package core

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

type cleanupRecorder struct {
	id    string
	order *[]string
}

func (m *cleanupRecorder) Init(*state.State) error {
	return nil
}

func (m *cleanupRecorder) Cleanup(*state.State) error {
	*m.order = append(*m.order, m.id)
	return nil
}

func TestStopCleansModulesInReverseInitializationOrder(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	order := make([]string, 0, 3)
	first := &cleanupRecorder{id: "first", order: &order}
	second := &cleanupRecorder{id: "second", order: &order}
	third := &cleanupRecorder{id: "third", order: &order}
	s := &state.State{
		Env: &state.Env{
			Context: ctx,
			Cancel:  cancel,
			Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		Modules:     make(map[string]state.NyModule),
		ModuleOrder: []state.NyModule{first, second, third},
	}

	Stop(s)

	assert.Equal(t, []string{"third", "second", "first"}, order)
}
