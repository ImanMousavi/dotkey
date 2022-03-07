package run

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ChainSafe/gossamer/lib/crypto"
	"github.com/ChainSafe/gossamer/lib/crypto/ed25519"
	"github.com/ChainSafe/gossamer/lib/crypto/sr25519"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/kubetrail/dotkey/pkg/flags"
	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	var prvKey crypto.PrivateKey
	switch len(b) {
	case 32:
		key := &sr25519.PrivateKey{}
		if err := key.Decode(b); err != nil {
			return fmt.Errorf("failed to decode private key")
		}
		prvKey = key
	case 64:
		key := &ed25519.PrivateKey{}
		if err := key.Decode(b); err != nil {
			return fmt.Errorf("failed to decode private key")
		}
		prvKey = key
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

	hash := ethcrypto.Keccak256(b)
	sign, err := prvKey.Sign(hash)
	if err != nil {
		return fmt.Errorf("failed to sign data: %w", err)
	}

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
