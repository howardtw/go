package crypto

import (
	"github.com/stellar/go/support/errors"
)

const awsPrefix = "aws-kms"

type KMS interface {
	Encrypt(plaintext, contextInfo []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext, contextInfo []byte) (plaintext []byte, err error)
}

func NewKMS(masterKeyURI, serviceKeyset string) (KMS, error) {
	if len(masterKeyURI) > 7 {
		prefix := masterKeyURI[0:7]
		switch prefix {
		case awsPrefix:
			return newSecureServiceKeyWithAWS(masterKeyURI, []byte(serviceKeyset))

		default:
			return nil, errors.New("KMS_MASTER_KEY_URI does not start with a valid prefix (aws-kms)")
		}
	}

	return newInsecureServiceKey([]byte(serviceKeyset))
}
