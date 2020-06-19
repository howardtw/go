package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEncrypterDecrypter(t *testing.T) {
	ksPriv := generateHybridKeysetCleartext(t)
	enc, dec, err := NewEncrypterDecrypter("", ksPriv)
	require.NoError(t, err)
	assert.NotNil(t, enc)
	assert.NotNil(t, dec)
}
