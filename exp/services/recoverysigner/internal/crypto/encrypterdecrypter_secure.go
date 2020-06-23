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
	aead, err := client.GetAEAD(kmsKeyURI)
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting AEAD primitive from KMS")
	}

	ksr := keyset.NewJSONReader(strings.NewReader(tinkKeysetJSON))
	ks, err := ksr.ReadEncrypted()

	d := &secureDecrypter{
		remote: aead,
		keyset: ks,
	}

	khPriv, err := keyset.Read(&keyset.MemReaderWriter{EncryptedKeyset: ks}, aead)
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting key handle for private key")
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
