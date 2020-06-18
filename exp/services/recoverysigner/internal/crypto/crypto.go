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

func NewEncrypter(remoteKEKURI string, keysetReader io.Reader) (Encrypter, error) {
	srvKey, err := newServiceKey(remoteKEKURI, keysetReader)
	if err != nil {
		return nil, errors.Wrap(err, "initializing service key")
	}

	encrypter, ok := srvKey.(Encrypter)
	if !ok {
		return nil, errors.New("service key is not an Encrypter")
	}

	return encrypter, nil
}

func NewDecrypter(remoteKEKURI string, keysetReader io.Reader) (Decrypter, error) {
	srvKey, err := newServiceKey(remoteKEKURI, keysetReader)
	if err != nil {
		return nil, errors.Wrap(err, "initializing service key")
	}

	decrypter, ok := srvKey.(Decrypter)
	if !ok {
		return nil, errors.New("service key is not a Decrypter")
	}

	return decrypter, nil
}

func newServiceKey(remoteKEKURI string, keysetReader io.Reader) (interface{}, error) {
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
