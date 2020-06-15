package crypto

import (
	"bytes"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/integration/awskms"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"
)

type SecureServiceKeySet struct {
	remote        tink.AEAD
	keyset        *tinkpb.EncryptedKeyset
	hybridEncrypt tink.HybridEncrypt
}

// masterKeyURI must have the following format: 'arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func NewSecureServiceKeySetWithAWS(masterKeyURI string, encryptedPrivateKey []byte) (*SecureServiceKeySet, error) {
	client, err := awskms.NewClient(masterKeyURI)
	if err != nil {
		return nil, err
	}

	registry.RegisterKMSClient(client)

	aead, err := client.GetAEAD(masterKeyURI)
	if err != nil {
		return nil, err
	}

	ksPriv, err := aead.Decrypt(encryptedPrivateKey, nil)
	if err != nil {
		return nil, err
	}

	khPriv, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(ksPriv)))
	if err != nil {
		return nil, err
	}

	// remove the decrypted private key from memory
	ksPriv = nil

	memKeyset := &keyset.MemReaderWriter{}
	err = khPriv.Write(memKeyset, aead)
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

	return &SecureServiceKeySet{
		remote:        aead,
		keyset:        memKeyset.EncryptedKeyset,
		hybridEncrypt: he,
	}, nil
}

func (ks *SecureServiceKeySet) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	return ks.hybridEncrypt.Encrypt(plaintext, contextInfo)
}

func (ks *SecureServiceKeySet) Decrypt(plaintext, contextInfo []byte) ([]byte, error) {
	khPriv, err := keyset.Read(&keyset.MemReaderWriter{EncryptedKeyset: ks.keyset}, ks.remote)
	if err != nil {
		return nil, err
	}

	hd, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		return nil, err
	}

	return hd.Decrypt(plaintext, contextInfo)
}
