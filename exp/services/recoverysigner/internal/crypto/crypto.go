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

func NewEncrypter(masterKeyURI, serviceKeyKeyset string) (Encrypter, error) {
	srvKey, err := newServiceKey(masterKeyURI, serviceKeyKeyset)
	if err != nil {
		return nil, err
	}

	encrypter, ok := srvKey.(Encrypter)
	if !ok {
		return nil, errors.New("service key is not an Encrypter")
	}

	return encrypter, nil
}

func NewDecrypter(masterKeyURI, serviceKeyKeyset string) (Decrypter, error) {
	srvKey, err := newServiceKey(masterKeyURI, serviceKeyKeyset)
	if err != nil {
		return nil, err
	}

	decrypter, ok := srvKey.(Decrypter)
	if !ok {
		return nil, errors.New("service key is not a Decrypter")
	}

	return decrypter, nil
}

func newServiceKey(masterKeyURI, serviceKeyKeyset string) (interface{}, error) {
	if len(masterKeyURI) > 7 {
		prefix := masterKeyURI[0:7]
		switch prefix {
		case awsPrefix:
			kmsClient, err := awskms.NewClient(masterKeyURI)
			if err != nil {
				return nil, errors.Wrap(err, "initializing AWS KMS client")
			}

			return newSecureServiceKey(kmsClient, masterKeyURI, []byte(serviceKeyKeyset))

		case "mockkms":
			return newSecureServiceKey(mockKMSClient{}, "mock-key-uri", []byte(serviceKeyKeyset))

		default:
			return nil, errors.New("unrecognized prefix in master key URI")
		}
	}

	return newInsecureServiceKey([]byte(serviceKeyKeyset))
}
