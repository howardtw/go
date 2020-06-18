package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInsecureServiceKey(t *testing.T) {
	ksPriv := generateHybridKeysetCleartext(t)
	serviceKey, err := newInsecureServiceKey(string(ksPriv))
	require.NoError(t, err)
	assert.NotNil(t, serviceKey)
	assert.NotNil(t, serviceKey.hybridEncrypt)
	assert.NotNil(t, serviceKey.hybridDecrypt)

	serviceKey, err = newInsecureServiceKey("")
	assert.Error(t, err)
	assert.Nil(t, serviceKey)
}

func TestInsecureServiceKey_encryptDecrypt(t *testing.T) {
	ksPriv := generateHybridKeysetCleartext(t)
	serviceKey, err := newInsecureServiceKey(string(ksPriv))
	require.NoError(t, err)

	plaintext := []byte("secure message")
	contextInfo := []byte("context info")
	ciphertext, err := serviceKey.Encrypt(plaintext, contextInfo)
	require.NoError(t, err)

	plaintext2, err := serviceKey.Decrypt(ciphertext, contextInfo)
	require.NoError(t, err)
	assert.Equal(t, plaintext, plaintext2)

	// context info not matching will result in a failed decryption
	_, err = serviceKey.Decrypt(ciphertext, []byte("wrong info"))
	assert.Error(t, err)
}
