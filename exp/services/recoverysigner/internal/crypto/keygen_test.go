package crypto

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"
)

func generateHybridKeysetCleartext(t *testing.T) []byte {
	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	require.NoError(t, err)

	memKeyset := &keyset.MemReaderWriter{}
	err = insecurecleartextkeyset.Write(khPriv, memKeyset)
	require.NoError(t, err)

	ksPriv, err := proto.Marshal(memKeyset.Keyset)
	require.NoError(t, err)

	return ksPriv
}

func generateHybridKeysetEncrypted(t *testing.T) []byte {
	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	require.NoError(t, err)

	memKeyset := &keyset.MemReaderWriter{}
	err = khPriv.Write(memKeyset, mockAEAD{})
	require.NoError(t, err)

	ksPriv, err := proto.Marshal(memKeyset.EncryptedKeyset)
	require.NoError(t, err)

	return ksPriv
}
