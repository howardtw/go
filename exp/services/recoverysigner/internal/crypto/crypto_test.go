package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEncrypter(t *testing.T) {
	ksPriv := generateHybridKeysetCleartext(t)
	encrypter, err := NewEncrypter("", string(ksPriv))
	require.NoError(t, err)
	assert.IsType(t, (*InsecureServiceKey)(nil), encrypter)
}

func TestNewDecrypter(t *testing.T) {
	ksPriv := generateHybridKeysetCleartext(t)
	decrypter, err := NewDecrypter("", string(ksPriv))
	require.NoError(t, err)
	assert.IsType(t, (*InsecureServiceKey)(nil), decrypter)
}
