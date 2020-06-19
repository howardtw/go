package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecureEncrypterDecrypter(t *testing.T) {
	ksPriv := generateHybridKeysetEncrypted(t)
	sed, err := newSecureEncrypterDecrypter(mockKMSClient{}, "aws-kms://key-uri", ksPriv)
	require.NoError(t, err)
	assert.NotNil(t, sed)
	assert.NotNil(t, sed.remote)
	assert.NotNil(t, sed.keyset)
	assert.NotNil(t, sed.hybridEncrypt)

	sed, err = newSecureEncrypterDecrypter(mockKMSClient{}, "mock-key-uri", "")
	assert.Error(t, err)
	assert.Nil(t, sed)
}

func TestSecureEncrypterDecrypter_encryptDecrypt(t *testing.T) {
	ksPriv := generateHybridKeysetEncrypted(t)
	sed, err := newSecureEncrypterDecrypter(mockKMSClient{}, "mock-key-uri", ksPriv)
	require.NoError(t, err)

	plaintext := []byte("secure message")
	contextInfo := []byte("context info")
	ciphertext, err := sed.Encrypt(plaintext, contextInfo)
	require.NoError(t, err)

	plaintext2, err := sed.Decrypt(ciphertext, contextInfo)
	require.NoError(t, err)
	assert.Equal(t, plaintext, plaintext2)

	// context info not matching will result in a failed decryption
	_, err = sed.Decrypt(ciphertext, []byte("wrong info"))
	assert.Error(t, err)
}
