package core

import (
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func TestForwardEntryToNodeReturnsNoRouteDuringShutdown(t *testing.T) {
	var nilRouter *NylonRouter
	entry, ok := nilRouter.ForwardEntryToNode("node-a")
	assert.False(t, ok)
	assert.Equal(t, RouteTableEntry{}, entry)

	router := &NylonRouter{}
	entry, ok = router.ForwardEntryToNode("node-a")
	assert.False(t, ok)
	assert.Equal(t, RouteTableEntry{}, entry)

	router.State = &state.State{}
	entry, ok = router.ForwardEntryToNode("node-a")
	assert.False(t, ok)
	assert.Equal(t, RouteTableEntry{}, entry)
}
