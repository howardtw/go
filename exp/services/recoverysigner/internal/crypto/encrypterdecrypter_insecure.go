package crypto

import (
	"strings"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"github.com/stellar/go/support/errors"
)

var _ tink.AEAD = (*InsecureEncrypterDecrypter)(nil)
var _ tink.HybridEncrypt = (*InsecureEncrypterDecrypter)(nil)
var _ tink.HybridDecrypt = (*InsecureEncrypterDecrypter)(nil)

type InsecureEncrypterDecrypter struct {
	hybridEncrypt tink.HybridEncrypt
	hybridDecrypt tink.HybridDecrypt
}

func newInsecureEncrypterDecrypter(tinkKeysetJSON string) (*InsecureEncrypterDecrypter, error) {
	khPriv, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(strings.NewReader(tinkKeysetJSON)))
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

	return &InsecureEncrypterDecrypter{
		hybridEncrypt: he,
		hybridDecrypt: hd,
	}, nil
}

func (ks *InsecureEncrypterDecrypter) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	return ks.hybridEncrypt.Encrypt(plaintext, contextInfo)
}

func (ks *InsecureEncrypterDecrypter) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	return ks.hybridDecrypt.Decrypt(ciphertext, contextInfo)
}
