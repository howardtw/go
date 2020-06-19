package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEncrypterDecrypter(t *testing.T) {
	ksPriv := generateHybridKeysetCleartext(t)
	srvKey, err := NewEncrypterDecrypter("", ksPriv)
	require.NoError(t, err)
	assert.IsType(t, (*InsecureEncrypterDecrypter)(nil), srvKey)
}
