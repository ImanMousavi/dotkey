package run

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/kubetrail/dotkey/pkg/flags"
	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ed25519"
)

func Sign(cmd *cobra.Command, args []string) error {
	_ = viper.BindPFlag(flags.Filename, cmd.Flags().Lookup(flags.Filename))
	fileName := viper.GetString(flags.Filename)

	prompt, err := getPromptStatus()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	if prompt {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter prv key: "); err != nil {
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

	var prvKey ed25519.PrivateKey
	switch len(b) {
	case 64:
		prvKey = ed25519.NewKeyFromSeed(b[:32])
		if !bytes.Equal(prvKey[32:], b[32:]) {
			return fmt.Errorf("invalid private key, derived publc key mismatch")
		}
	default:
		return fmt.Errorf("invalid key length, expected 64, got %d", len(b))
	}

	if len(fileName) > 0 {
		if fileName == "-" {
			if b, err = io.ReadAll(cmd.InOrStdin()); err != nil {
				return fmt.Errorf("failed to read stdin input: %w", err)
			}
		} else {
			if b, err = os.ReadFile(fileName); err != nil {
				return fmt.Errorf("failed to read input file %s: %w", fileName, err)
			}
		}
	} else {
		if len(args) == 0 {
			return fmt.Errorf("no input file or args, pl. provide input to sign")
		}
		b = []byte(strings.Join(args, " "))
	}

	hash := crypto.Keccak256(b)
	sign := ed25519.Sign(prvKey, hash)

	hashB58 := base58.Encode(hash)
	signB58 := base58.Encode(sign)

	if prompt {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "hash: ", hashB58); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}

		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "sign: ", signB58); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}

		return nil
	}

	jb, err := json.Marshal(
		struct {
			Hash string `json:"hash,omitempty"`
			Sign string `json:"sign,omitempty"`
		}{
			Hash: hashB58,
			Sign: signB58,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to serialize output: %w", err)
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(jb)); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	return nil
}
