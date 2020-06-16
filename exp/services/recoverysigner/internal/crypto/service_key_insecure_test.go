package crypto

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInsecureServiceKey(t *testing.T) {
	ksPriv := generateHybridEncryptionPrivateKeyKeyset(t)
	serviceKey, err := newInsecureServiceKey(ksPriv)
	require.NoError(t, err)
	assert.NotNil(t, serviceKey)
	assert.NotNil(t, serviceKey.hybridEncrypt)
	assert.NotNil(t, serviceKey.hybridDecrypt)
}

func TestInsecureServiceKey_encryptDecrypt(t *testing.T) {
	ksPriv := generateHybridEncryptionPrivateKeyKeyset(t)
	serviceKey, err := newInsecureServiceKey(ksPriv)
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

func generateHybridEncryptionPrivateKeyKeyset(t *testing.T) []byte {
	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	require.NoError(t, err)

	exportedPriv := &keyset.MemReaderWriter{}
	err = insecurecleartextkeyset.Write(khPriv, exportedPriv)
	require.NoError(t, err)

	ksPriv, err := proto.Marshal(exportedPriv.Keyset)
	require.NoError(t, err)

	return ksPriv
}
