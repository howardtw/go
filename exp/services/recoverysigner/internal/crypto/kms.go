package crypto

import (
	"github.com/google/tink/go/integration/awskms"
	"github.com/stellar/go/support/errors"
)

const awsPrefix = "aws-kms"

type KMS interface {
	Encrypt(plaintext, contextInfo []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext, contextInfo []byte) (plaintext []byte, err error)
}

func NewKMS(masterKeyURI, serviceKeyKeyset string) (KMS, error) {
	if len(masterKeyURI) > 7 {
		prefix := masterKeyURI[0:7]
		switch prefix {
		case awsPrefix:
			kmsClient, err := awskms.NewClient(masterKeyURI)
			if err != nil {
				return nil, errors.Wrap(err, "initializing AWS KMS client")
			}

			return newSecureServiceKey(kmsClient, masterKeyURI, []byte(serviceKeyKeyset))

		default:
			return nil, errors.New("unrecognized prefix in master key URI")
		}
	}

	return newInsecureServiceKey([]byte(serviceKeyKeyset))
}
