package crypto

import (
	"strings"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"github.com/stellar/go/support/errors"
	supportlog "github.com/stellar/go/support/log"
)

func newInsecureEncrypterDecrypter(l *supportlog.Entry, tinkKeysetPrivateJSON, tinkKeysetPublicJSON string) (Encrypter, Decrypter, error) {
	if tinkKeysetPrivateJSON == "" && tinkKeysetPublicJSON == "" {
		l.Warn("Encrypter and decrypter are not configured. Account registration and signing operation will not be working.")
		return nil, nil, nil
	}

	var (
		hd     tink.HybridDecrypt
		he     tink.HybridEncrypt
		khPriv *keyset.Handle
		khPub  *keyset.Handle
		err    error
	)

	if tinkKeysetPrivateJSON != "" {
		khPriv, err = insecurecleartextkeyset.Read(keyset.NewJSONReader(strings.NewReader(tinkKeysetPrivateJSON)))
		if err != nil {
			return nil, nil, errors.Wrap(err, "getting key handle for private key")
		}

		hd, err = hybrid.NewHybridDecrypt(khPriv)
		if err != nil {
			return nil, nil, errors.Wrap(err, "getting hybrid decryption primitive")
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
	if he != nil && hd == nil {
		l.Warn("Decrypter is not configured. Signing operation will not be working.")
		l.Warn("Please make sure that you have the access to keyset private. Otherwise you will not be able to sign with the new signer generated during account registration.")
		return he, nil, nil
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

	return he, hd, nil
}
