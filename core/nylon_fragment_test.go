package core

import (
	"testing"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/stretchr/testify/assert"
)

func TestMaxPlaintextForTransportMTUIncludesWireGuardOverhead(t *testing.T) {
	got := maxPlaintextForTransportMTU(1400, 1420)

	assert.Equal(t, 1360, got)
	assert.LessOrEqual(t, device.MessageTransportSize+got+wireGuardPaddingSize(got, 1420), 1400)
	assert.Greater(t, device.MessageTransportSize+got+1+wireGuardPaddingSize(got+1, 1420), 1400)
}
