package run

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"strings"

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

	hashBytes, err := base58.Decode(hash)
	if err != nil {
		return fmt.Errorf("failed to decode hash: %w", err)
	}

	signBytes, err := base58.Decode(sign)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if !ed25519.Verify(b, hashBytes, signBytes) {
		return fmt.Errorf("failed to validate signature")
	}

	if printOk {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "signature is valid for given hash and public key"); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
	}

	return nil
}
