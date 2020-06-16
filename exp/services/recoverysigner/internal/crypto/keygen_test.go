package crypto

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"
)

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
