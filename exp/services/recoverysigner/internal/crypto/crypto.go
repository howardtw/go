package crypto

import (
	"github.com/google/tink/go/integration/awskms"
	"github.com/stellar/go/support/errors"
)

const awsPrefix = "aws-kms"

type Encrypter interface {
	Encrypt(plaintext, contextInfo []byte) (ciphertext []byte, err error)
}

type Decrypter interface {
	Decrypt(ciphertext, contextInfo []byte) (plaintext []byte, err error)
}

func NewEncrypterDecrypter(kmsKeyURI, tinkKeysetJSON string) (interface{}, error) {
	if len(kmsKeyURI) == 0 {
		return newInsecureEncrypterDecrypter(tinkKeysetJSON)
	}

	if len(kmsKeyURI) <= 7 {
		return nil, errors.New("invalid KMS key URI format")
	}

	prefix := kmsKeyURI[0:7]
	switch prefix {
	case awsPrefix:
		kmsClient, err := awskms.NewClient(kmsKeyURI)
		if err != nil {
			return nil, errors.Wrap(err, "initializing AWS KMS client")
		}

		return newSecureEncrypterDecrypter(kmsClient, kmsKeyURI, tinkKeysetJSON)

	default:
		return nil, errors.New("unrecognized prefix in KMS Key URI")
	}
}
