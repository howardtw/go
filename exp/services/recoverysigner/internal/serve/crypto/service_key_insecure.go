package crypto

import (
	"bytes"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"github.com/stellar/go/support/errors"
)

type InsecureServiceKeySet struct {
	hybridEncrypt tink.HybridEncrypt
	hybridDecrypt tink.HybridDecrypt
}

func newInsecureServiceKeySet(privateKey []byte) (*InsecureServiceKeySet, error) {
	if len(privateKey) == 0 {
		return nil, errors.New("SERVICE_KEY_PRIVATE is empty")
	}

	khPriv, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(privateKey)))
	if err != nil {
		return nil, errors.Wrap(err, "getting key handle for private key")
	}

	hd, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		return nil, errors.Wrap(err, "getting hybrid decryption primitive")
	}

	khPub, err := khPriv.Public()
	if err != nil {
		return nil, errors.Wrap(err, "getting key handle for public key")
	}

	he, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return nil, errors.Wrap(err, "getting hybrid encryption primitive")
	}

	return &InsecureServiceKeySet{
		hybridEncrypt: he,
		hybridDecrypt: hd,
	}, nil
}

func (ks *InsecureServiceKeySet) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	return ks.hybridEncrypt.Encrypt(plaintext, contextInfo)
}

func (ks *InsecureServiceKeySet) Decrypt(plaintext, contextInfo []byte) ([]byte, error) {
	return ks.hybridDecrypt.Decrypt(plaintext, contextInfo)
}
