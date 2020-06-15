package crypto

import (
	"bytes"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

type InsecureServiceKeySet struct {
	hybridEncrypt tink.HybridEncrypt
	hybridDecrypt tink.HybridDecrypt
}

func NewInsecureServiceKeySet(privateKey []byte) (*InsecureServiceKeySet, error) {
	khPriv, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(privateKey)))
	if err != nil {
		return nil, err
	}

	hd, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		return nil, err
	}

	khPub, err := khPriv.Public()
	if err != nil {
		return nil, err
	}

	he, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return nil, err
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
