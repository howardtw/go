package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInsecureEncrypterDecrypter(t *testing.T) {
	ksPriv := generateHybridKeysetCleartext(t)
	ied, err := newInsecureEncrypterDecrypter(ksPriv)
	require.NoError(t, err)
	assert.NotNil(t, ied)
	assert.NotNil(t, ied.hybridEncrypt)
	assert.NotNil(t, ied.hybridDecrypt)

	ied, err = newInsecureEncrypterDecrypter("")
	assert.Error(t, err)
	assert.Nil(t, ied)
}

func TestInsecureEncrypterDecrypter_encryptDecrypt(t *testing.T) {
	ksPriv := generateHybridKeysetCleartext(t)
	ied, err := newInsecureEncrypterDecrypter(ksPriv)
	require.NoError(t, err)

	plaintext := []byte("secure message")
	contextInfo := []byte("context info")
	ciphertext, err := ied.Encrypt(plaintext, contextInfo)
	require.NoError(t, err)

	plaintext2, err := ied.Decrypt(ciphertext, contextInfo)
	require.NoError(t, err)
	assert.Equal(t, plaintext, plaintext2)

	// context info not matching will result in a failed decryption
	_, err = ied.Decrypt(ciphertext, []byte("wrong info"))
	assert.Error(t, err)
}
