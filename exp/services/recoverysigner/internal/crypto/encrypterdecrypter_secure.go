package crypto

import (
	"strings"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"
	"github.com/stellar/go/support/errors"
	supportlog "github.com/stellar/go/support/log"
)

type secureDecrypter struct {
	remote tink.AEAD
	keyset *tinkpb.EncryptedKeyset
}

// kmsKeyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func newSecureEncrypterDecrypter(l *supportlog.Entry, client registry.KMSClient, kmsKeyURI, tinkKeysetPrivateJSON, tinkKeysetPublicJSON string) (Encrypter, Decrypter, error) {
	if tinkKeysetPrivateJSON == "" && tinkKeysetPublicJSON == "" {
		l.Warn("Encrypter and decrypter are not configured. Account registration and signing operation will not be working.")
		return nil, nil, nil
	}

	var (
		sd    *secureDecrypter
		he    tink.HybridEncrypt
		khPub *keyset.Handle
		err   error
	)

	if tinkKeysetPrivateJSON != "" {
		var aead tink.AEAD
		var ks *tinkpb.EncryptedKeyset
		aead, err = client.GetAEAD(kmsKeyURI)
		if err != nil {
			return nil, nil, errors.Wrap(err, "getting AEAD primitive from KMS")
		}

		ks, err = keyset.NewJSONReader(strings.NewReader(tinkKeysetPrivateJSON)).ReadEncrypted()
		if err != nil {
			return nil, nil, errors.Wrap(err, "reading encrypted keyset")
		}

		sd = &secureDecrypter{
			remote: aead,
			keyset: ks,
		}
	}

	if tinkKeysetPublicJSON != "" {
		khPub, err = keyset.ReadWithNoSecrets(keyset.NewJSONReader(strings.NewReader(tinkKeysetPublicJSON)))
		if err != nil {
			return nil, nil, errors.Wrap(err, "getting key handle for public key")
		}

		he, err = hybrid.NewHybridEncrypt(khPub)
		if err != nil {
			return nil, nil, errors.Wrap(err, "getting hybrid encryption primitive")
		}
	}

	// Only Encrypter is available. No way to get Decrypter from Encrypter.
	if he != nil && sd == nil {
		l.Warn("Decrypter is not configured. Signing operation will not be working.")
		l.Warn("Please make sure that you have the access to keyset private. Otherwise you will not be able to sign with the new signer generated during account registration.")
		return he, nil, nil
	}

	// Though unlikely, it is possible we will have trouble contacting AWS
	// KMS. We will swallow the error to start the service and let the
	// deployers run the system at their own risk.
	khPriv, err := keyset.Read(&keyset.MemReaderWriter{EncryptedKeyset: sd.keyset}, sd.remote)
	if err != nil {
		if he == nil {
			l.Warn("Encrypter is not configured. Account registration will not be working.")
		}
		l.Warn("Unable to decrypt the encrypted keyset. We are not able to verify whether the decrypter will work properly at this moment:", err)
		return he, sd, nil
	}

	// When Decrypter is available, we can
	// 1. get Encrypter if tinkKeysetPublicJSON is not provided.
	// 2. verify Encrypter is compatible with Decrypter.
	khPubv, err := khPriv.Public()
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting key handle for public key")
	}

	if khPub == nil {
		// get Encrypter
		he, err = hybrid.NewHybridEncrypt(khPubv)
		if err != nil {
			return nil, nil, errors.Wrap(err, "getting hybrid encryption primitive")
		}
	} else {
		// verify Encrypter is compatible with Decrypter
		if khPub.String() != khPubv.String() {
			l.Info("The provided keyset public and the derived keyset public don't match.")
			l.Info("The provided keyset public:", khPub.String())
			l.Info("The derived keyset public:", khPubv.String())

			// We could also use the best effort to get a encrypter
			// and ignore the provided keyset public. This,
			// however, is a bad idea given that we don't know
			// which keyset is set wrong. It's best not making any
			// assumption here.
			return nil, nil, errors.New("incompatible encrypter and decrypter")
		}
	}

	return he, sd, nil
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
