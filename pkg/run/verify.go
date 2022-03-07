package run

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/ChainSafe/gossamer/lib/crypto"
	"github.com/ChainSafe/gossamer/lib/crypto/ed25519"
	"github.com/ChainSafe/gossamer/lib/crypto/sr25519"
	"github.com/kubetrail/dotkey/pkg/flags"
	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Verify(cmd *cobra.Command, args []string) error {
	_ = viper.BindPFlag(flags.Hash, cmd.Flags().Lookup(flags.Hash))
	_ = viper.BindPFlag(flags.Sign, cmd.Flags().Lookup(flags.Sign))
	_ = viper.BindPFlag(flags.PubKey, cmd.Flags().Lookup(flags.PubKey))

	hash := viper.GetString(flags.Hash)
	sign := viper.GetString(flags.Sign)
	key := viper.GetString(flags.PubKey)

	printOk := false
	if len(hash) == 0 ||
		len(sign) == 0 ||
		len(key) == 0 {
		printOk = true
	}

	inputReader := bufio.NewReader(cmd.InOrStdin())
	prompt, err := getPromptStatus()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	if len(key) == 0 {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter pub key: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
		key, err = inputReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read pub key from input: %w", err)
		}
		key = strings.Trim(key, "\n")
	}

	if len(hash) == 0 {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter hash: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
		hash, err = inputReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read hash from input: %w", err)
		}
		hash = strings.Trim(hash, "\n")
	}

	if len(sign) == 0 {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter sign: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
		sign, err = inputReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read sign from input: %w", err)
		}
		sign = strings.Trim(sign, "\n")
	}

	b, err := base58.Decode(key)
	if err != nil {
		return fmt.Errorf("failed to decode key as base58 string: %w", err)
	}

	if len(b) != 35 {
		return fmt.Errorf("invalid public key byte length, expected 35, got %d", len(b))
	}

	hashBytes, err := base58.Decode(hash)
	if err != nil {
		return fmt.Errorf("failed to decode hash: %w", err)
	}

	signBytes, err := base58.Decode(sign)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	var pubKey crypto.PublicKey

	decodeErr := fmt.Errorf("")

	if decodeErr != nil {
		key := &sr25519.PublicKey{}
		if err := key.Decode(b[1:33]); err != nil {
			decodeErr = fmt.Errorf("failed to decode as sr25519 public key: %w", err)
		} else {
			decodeErr = nil
			pubKey = key
		}
	}

	if decodeErr != nil {
		key := &ed25519.PublicKey{}
		if err := key.Decode(b[1:33]); err != nil {
			decodeErr = fmt.Errorf("failed to decode as ed25519 public key: %w", err)
		} else {
			decodeErr = nil
			pubKey = key
		}
	}

	if decodeErr != nil {
		return decodeErr
	}

	if ok, err := pubKey.Verify(hashBytes, signBytes); err != nil || !ok {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	if printOk {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "signature is valid for given hash and public key"); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
	}

	return nil
}
