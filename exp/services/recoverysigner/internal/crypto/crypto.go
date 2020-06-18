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

func NewEncrypter(remoteKEKURI, tinkKeyset string) (Encrypter, error) {
	srvKey, err := newServiceKey(remoteKEKURI, tinkKeyset)
	if err != nil {
		return nil, err
	}

	encrypter, ok := srvKey.(Encrypter)
	if !ok {
		return nil, errors.New("service key is not an Encrypter")
	}

	return encrypter, nil
}

func NewDecrypter(remoteKEKURI, tinkKeyset string) (Decrypter, error) {
	srvKey, err := newServiceKey(remoteKEKURI, tinkKeyset)
	if err != nil {
		return nil, err
	}

	decrypter, ok := srvKey.(Decrypter)
	if !ok {
		return nil, errors.New("service key is not a Decrypter")
	}

	return decrypter, nil
}

func newServiceKey(remoteKEKURI, tinkKeyset string) (interface{}, error) {
	if len(remoteKEKURI) == 0 {
		return newInsecureServiceKey([]byte(tinkKeyset))
	}

	if len(remoteKEKURI) <= 7 {
		return nil, errors.New("invalid remote KEK URI format")
	}

	prefix := remoteKEKURI[0:7]
	switch prefix {
	case awsPrefix:
		kmsClient, err := awskms.NewClient(remoteKEKURI)
		if err != nil {
			return nil, errors.Wrap(err, "initializing AWS KMS client")
		}

		return newSecureServiceKey(kmsClient, remoteKEKURI, []byte(tinkKeyset))

	case "mockkms":
		return newSecureServiceKey(mockKMSClient{}, "mock-key-uri", []byte(tinkKeyset))

	default:
		return nil, errors.New("unrecognized prefix in remote KEK URI")
	}
}
