package crypto

import (
	"io"
	"io/ioutil"

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

func NewServiceKey(remoteKEKURI string, keysetReader io.Reader) (interface{}, error) {
	tinkKeyset, err := ioutil.ReadAll(keysetReader)
	if err != nil {
		return nil, errors.Wrap(err, "reading keyset from the file path")
	}

	if len(remoteKEKURI) == 0 {
		return newInsecureServiceKey(tinkKeyset)
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

		return newSecureServiceKey(kmsClient, remoteKEKURI, tinkKeyset)

	default:
		return nil, errors.New("unrecognized prefix in remote KEK URI")
	}
}
