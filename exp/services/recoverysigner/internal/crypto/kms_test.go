package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKMS(t *testing.T) {
	ksPriv := generateHybridEncryptionPrivateKeyKeyset(t)
	kms, err := NewKMS("mockkms://key-uri", string(ksPriv))
	require.NoError(t, err)
	assert.IsType(t, (*SecureServiceKey)(nil), kms)

	kms, err = NewKMS("", string(ksPriv))
	require.NoError(t, err)
	assert.IsType(t, (*InsecureServiceKey)(nil), kms)
}
