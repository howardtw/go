package crypto

import (
	"github.com/stellar/go/support/errors"
)

const (
	awsPrefix = "aws-kms"
	gcpPrefix = "gcp-kms"
)

type KMS interface {
	Encrypt(plaintext, contextInfo []byte) ([]byte, error)
	Decrypt(plaintext, contextInfo []byte) ([]byte, error)
}

func NewKMS(masterKeyURI, encryptedServiceKeyPrivate, serviceKeyPrivate string) (KMS, error) {
	if len(masterKeyURI) > 7 {
		prefix := masterKeyURI[0:7]

		switch prefix {
		case awsPrefix:
			return newSecureServiceKeySetWithAWS(masterKeyURI, []byte(encryptedServiceKeyPrivate))

		default:
			return nil, errors.New("KMS_MASTER_KEY_URI does not start with a valid prefix (aws-kms)")
		}
	}

	return newInsecureServiceKeySet([]byte(serviceKeyPrivate))
}
