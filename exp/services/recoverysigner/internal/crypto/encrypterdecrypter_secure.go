package crypto

import (
	"strings"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"
	"github.com/stellar/go/support/errors"
)

// kmsKeyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func newSecureEncrypterDecrypter(client registry.KMSClient, kmsKeyURI, tinkKeysetJSON string) (Encrypter, Decrypter, error) {
	// The registration of the KMS client is only necessary if we want to
	// use KMSEnvelopeAEAD. In other words, this is not required since we
	// are not using envelope encryption to encrypt/decrypt the Tink
	// keyset. However, it doesn't hurt to leave it here to be defensive in
	// case we change the strategy.
	registry.RegisterKMSClient(client)

	aead, err := client.GetAEAD(kmsKeyURI)
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting AEAD primitive from KMS")
	}

	khPriv, err := keyset.Read(keyset.NewJSONReader(strings.NewReader(tinkKeysetJSON)), aead)
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting key handle for private key")
	}

	memKeyset := &keyset.MemReaderWriter{}
	err = khPriv.Write(memKeyset, aead)
	if err != nil {
		return nil, nil, errors.Wrap(err, "encrypting keyset")
	}

	d := &secureDecrypter{
		remote: aead,
		keyset: memKeyset.EncryptedKeyset,
	}

	khPub, err := khPriv.Public()
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting key handle for public key")
	}

	he, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting hybrid encryption primitive")
	}

	return he, d, nil
}

type secureDecrypter struct {
	remote tink.AEAD
	keyset *tinkpb.EncryptedKeyset
}

func (ks *secureDecrypter) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	khPriv, err := keyset.Read(&keyset.MemReaderWriter{EncryptedKeyset: ks.keyset}, ks.remote)
	if err != nil {
		return nil, errors.Wrap(err, "decrypting keyset")
	}

	hd, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		return nil, errors.Wrap(err, "getting hybrid decryption primitive")
	}

	return hd.Decrypt(ciphertext, contextInfo)
}
