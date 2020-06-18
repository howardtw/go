package cmd

import (
	"go/types"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/integration/awskms"
	"github.com/google/tink/go/keyset"
	"github.com/spf13/cobra"
	"github.com/stellar/go/support/config"
	supportlog "github.com/stellar/go/support/log"
)

type KeysetCommand struct {
	Logger         *supportlog.Entry
	RemoteKEKURI   string
	OutputFilePath string
}

func (c *KeysetCommand) Command() *cobra.Command {
	configOpts := config.ConfigOptions{
		{
			Name:        "remote-kek-uri",
			Usage:       "URI for a remote key-encryption-key (KEK) used to encrypt Tink keyset",
			OptType:     types.String,
			ConfigKey:   &c.RemoteKEKURI,
			FlagDefault: "",
			Required:    false,
		},
		{
			Name:        "output-filepath",
			Usage:       "File path to which the keyset is written",
			OptType:     types.String,
			ConfigKey:   &c.OutputFilePath,
			FlagDefault: "",
			Required:    false,
		},
	}
	cmd := &cobra.Command{
		Use:   "keyset",
		Short: "Run Tink keyset operations",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			configOpts.SetValues()
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	configOpts.Init(cmd)

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new Tink keyset",
		Run: func(_ *cobra.Command, _ []string) {
			c.Create()
		},
	}
	cmd.AddCommand(createCmd)

	return cmd
}

func (c *KeysetCommand) Create() {
	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		c.Logger.Errorf("Error generating a new keyset: %s", err.Error())
		return
	}

	memKeyset := &keyset.MemReaderWriter{}
	ksPriv := []byte{}
	if c.RemoteKEKURI != "" {
		kmsClient, err := awskms.NewClient(c.RemoteKEKURI)
		if err != nil {
			c.Logger.Errorf("Error initializing AWS KMS client: %s", err.Error())
			return
		}

		aead, err := kmsClient.GetAEAD(c.RemoteKEKURI)
		if err != nil {
			c.Logger.Errorf("Error getting AEAD primitive from KMS: %s", err.Error())
			return
		}

		err = khPriv.Write(memKeyset, aead)
		if err != nil {
			c.Logger.Errorf("Error writing encrypted keyset: %s", err.Error())
			return
		}

		ksPriv, err = proto.Marshal(memKeyset.EncryptedKeyset)
		if err != nil {
			c.Logger.Errorf("Error serializing encrypted keyset: %s", err.Error())
			return
		}
	} else {
		err = insecurecleartextkeyset.Write(khPriv, memKeyset)
		if err != nil {
			c.Logger.Errorf("Error writing cleartext keyset: %s", err.Error())
			return
		}

		ksPriv, err = proto.Marshal(memKeyset.Keyset)
		if err != nil {
			c.Logger.Errorf("Error serializing cleartext keyset: %s", err.Error())
			return
		}
	}

	filePath := "keyset.cfg"
	if c.OutputFilePath != "" {
		filePath = c.OutputFilePath
	}

	f, err := os.OpenFile(filePath, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		c.Logger.Errorf("Error opening output file: %s", err.Error())
		return
	}
	defer f.Close()

	_, err = f.Write(ksPriv)
	if err != nil {
		c.Logger.Errorf("Error writing to output file: %s", err.Error())
		return
	}

	c.Logger.Info("Tink keyset has been written to a file. The default file name is 'keyset.cfg'.")
}
