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
	"github.com/stellar/go/support/errors"
)

type SecureServiceKey struct {
	remote        tink.AEAD
	keyset        *tinkpb.EncryptedKeyset
	hybridEncrypt tink.HybridEncrypt
}

// masterKeyURI must have the following format: 'arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func newSecureServiceKeyWithAWS(masterKeyURI string, encryptedPrivateKey []byte) (*SecureServiceKey, error) {
	if len(encryptedPrivateKey) == 0 {
		return nil, errors.New("ENCRYPTED_SERVICE_KEY_PRIVATE is empty")
	}

	client, err := awskms.NewClient(masterKeyURI)
	if err != nil {
		return nil, errors.Wrap(err, "initializing AWS KMS client")
	}

	registry.RegisterKMSClient(client)

	aead, err := client.GetAEAD(masterKeyURI)
	if err != nil {
		return nil, errors.Wrap(err, "getting AEAD primitive from AWS KMS")
	}

	ksPriv, err := aead.Decrypt(encryptedPrivateKey, nil)
	if err != nil {
		return nil, errors.Wrap(err, "decrypting private key")
	}

	khPriv, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(ksPriv)))
	if err != nil {
		return nil, errors.Wrap(err, "getting key handle for private key")
	}

	// remove the decrypted private key from memory
	ksPriv = nil

	memKeyset := &keyset.MemReaderWriter{}
	err = khPriv.Write(memKeyset, aead)
	if err != nil {
		return nil, errors.Wrap(err, "encrypting private key keyset")
	}

	khPub, err := khPriv.Public()
	if err != nil {
		return nil, errors.Wrap(err, "getting key handle for public key")
	}

	he, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return nil, errors.Wrap(err, "getting hybrid encryption primitive")
	}

	return &SecureServiceKey{
		remote:        aead,
		keyset:        memKeyset.EncryptedKeyset,
		hybridEncrypt: he,
	}, nil
}

func (ks *SecureServiceKey) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	return ks.hybridEncrypt.Encrypt(plaintext, contextInfo)
}

func (ks *SecureServiceKey) Decrypt(plaintext, contextInfo []byte) ([]byte, error) {
	khPriv, err := keyset.Read(&keyset.MemReaderWriter{EncryptedKeyset: ks.keyset}, ks.remote)
	if err != nil {
		return nil, errors.Wrap(err, "decrypting private key keyset")
	}

	hd, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		return nil, errors.Wrap(err, "getting hybrid decryption primitive")
	}

	return hd.Decrypt(plaintext, contextInfo)
}
