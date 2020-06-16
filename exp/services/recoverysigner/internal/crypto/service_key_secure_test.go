package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecureServiceKey(t *testing.T) {
	ksPriv := generateHybridEncryptionPrivateKeyKeyset(t)
	encryptedKsPriv, err := mockAEAD{}.Encrypt(ksPriv, nil)
	require.NoError(t, err)

	serviceKey, err := newSecureServiceKey(mockKMSClient{}, "aws-kms://key-uri", encryptedKsPriv)
	require.NoError(t, err)
	assert.NotNil(t, serviceKey)
	assert.NotNil(t, serviceKey.remote)
	assert.NotNil(t, serviceKey.keyset)
	assert.NotNil(t, serviceKey.hybridEncrypt)

	serviceKey, err = newSecureServiceKey(mockKMSClient{}, "mock-key-uri", []byte(""))
	assert.Error(t, err)
	assert.Nil(t, serviceKey)
}

func TestSecureServiceKey_encryptDecrypt(t *testing.T) {
	ksPriv := generateHybridEncryptionPrivateKeyKeyset(t)
	encryptedKsPriv, err := mockAEAD{}.Encrypt(ksPriv, nil)
	require.NoError(t, err)

	serviceKey, err := newSecureServiceKey(mockKMSClient{}, "mock-key-uri", encryptedKsPriv)

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
