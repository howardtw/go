package crypto

import (
	"bytes"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"
	"github.com/stellar/go/support/errors"
)

var _ tink.AEAD = (*SecureServiceKey)(nil)
var _ tink.HybridEncrypt = (*SecureServiceKey)(nil)
var _ tink.HybridDecrypt = (*SecureServiceKey)(nil)

type SecureServiceKey struct {
	remote        tink.AEAD
	keyset        *tinkpb.EncryptedKeyset
	hybridEncrypt tink.HybridEncrypt
}

// masterKeyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func newSecureServiceKey(client registry.KMSClient, masterKeyURI string, encryptedServiceKeyKeyset []byte) (*SecureServiceKey, error) {
	if len(encryptedServiceKeyKeyset) == 0 {
		return nil, errors.New("no service key keyset is present")
	}

	registry.RegisterKMSClient(client)

	aead, err := client.GetAEAD(masterKeyURI)
	if err != nil {
		return nil, errors.Wrap(err, "getting AEAD primitive from KMS")
	}

	ksPriv, err := aead.Decrypt(encryptedServiceKeyKeyset, nil)
	if err != nil {
		return nil, errors.Wrap(err, "decrypting service key keyset")
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
		return nil, errors.Wrap(err, "encrypting service key keyset")
	}

	khPub, err := khPriv.Public()
	if err != nil {
		return nil, errors.Wrap(err, "getting key handle for public key")
	}

	he, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return nil, errors.Wrap(err, "getting hybrid encryption service key primitive")
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

func (ks *SecureServiceKey) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	khPriv, err := keyset.Read(&keyset.MemReaderWriter{EncryptedKeyset: ks.keyset}, ks.remote)
	if err != nil {
		return nil, errors.Wrap(err, "decrypting service key keyset")
	}

	hd, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		return nil, errors.Wrap(err, "getting hybrid decryption service key primitive")
	}

	return hd.Decrypt(ciphertext, contextInfo)
}