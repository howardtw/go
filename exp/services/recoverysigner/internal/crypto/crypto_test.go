package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServiceKey(t *testing.T) {
	ksPriv := generateHybridKeysetCleartext(t)
	srvKey, err := NewServiceKey("", bytes.NewReader(ksPriv))
	require.NoError(t, err)
	assert.IsType(t, (*InsecureServiceKey)(nil), srvKey)
}
