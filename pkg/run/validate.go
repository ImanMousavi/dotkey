package run

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ed25519"
)

func Validate(cmd *cobra.Command, args []string) error {
	prompt, err := getPromptStatus()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	if prompt {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter prv or pub key: "); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
	}

	inputReader := bufio.NewReader(cmd.InOrStdin())
	key, err := inputReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read mnemonic from input: %w", err)
	}
	key = strings.Trim(key, "\n")

	b, err := base58.Decode(key)
	if err != nil {
		return fmt.Errorf("failed to decode key as base58 string: %w", err)
	}

	switch len(b) {
	case 32:
		if prompt {
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "public key is valid"); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
	case 64:
		prvKey := ed25519.NewKeyFromSeed(b[:32])
		if !bytes.Equal(prvKey[32:], b[32:]) {
			return fmt.Errorf("invalid private key, derived publc key mismatch")
		}
		if prompt {
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "private key is valid"); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
	default:
		return fmt.Errorf("invalid key length")
	}

	return nil
}
