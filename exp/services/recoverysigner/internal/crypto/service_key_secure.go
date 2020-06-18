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

// remoteKEKURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func newSecureServiceKey(client registry.KMSClient, remoteKEKURI, encryptedTinkKeyset string) (*SecureServiceKey, error) {
	if len(encryptedTinkKeyset) == 0 {
		return nil, errors.New("no keyset is present")
	}

	// The registration of the KMS client is only necessary if we want to
	// use KMSEnvelopeAEAD. In other words, this is not required since we
	// are not using envelope encryption to encrypt/decrypt the Tink
	// keyset. However, it is ok to leave it here to defensive in case we
	// change the strategy since it doesn't hurt.
	registry.RegisterKMSClient(client)

	aead, err := client.GetAEAD(remoteKEKURI)
	if err != nil {
		return nil, errors.Wrap(err, "getting AEAD primitive from KMS")
	}

	ksPriv, err := aead.Decrypt([]byte(encryptedTinkKeyset), nil)
	if err != nil {
		return nil, errors.Wrap(err, "decrypting keyset")
	}

	khPriv, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(ksPriv)))
	if err != nil {
		return nil, errors.Wrap(err, "getting key handle for private key")
	}

	// remove the reference to the decrypted private key from memory
	ksPriv = nil

	memKeyset := &keyset.MemReaderWriter{}
	err = khPriv.Write(memKeyset, aead)
	if err != nil {
		return nil, errors.Wrap(err, "encrypting keyset")
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
