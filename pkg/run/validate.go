package run

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ChainSafe/gossamer/lib/crypto/ed25519"

	"github.com/ChainSafe/gossamer/lib/crypto/sr25519"
	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
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
		prv := &sr25519.PrivateKey{}
		if err := prv.Decode(b); err != nil {
			return fmt.Errorf("failed to decode private key")
		}
		if prompt {
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "sr25519 private key is valid"); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
	case 64:
		prv := &ed25519.PrivateKey{}
		if err := prv.Decode(b); err != nil {
			return fmt.Errorf("failed to decode private key")
		}
		if prompt {
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "ed25519 private key is valid"); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
	case 35:
		if err := populateRegistry(); err != nil {
			return fmt.Errorf("failed to populate registry: %w", err)
		}

		network := ""
		n := hex.EncodeToString(b[:1])
		for k, v := range networks {
			if n == v {
				network = k
				break
			}
		}

		if len(network) == 0 {
			return fmt.Errorf("invalid public key, network not detected: %s", n)
		}

		encode := make([]byte, 33)
		copy(encode, b[:33])

		hash, err := blake2b.New(64, nil)
		if err != nil {
			return fmt.Errorf("failed to generate blake2b hash func: %w", err)
		}
		if _, err := hash.Write(append(ss58Prefix, encode...)); err != nil {
			return fmt.Errorf("failed to hash data: %w", err)
		}
		checksum := hash.Sum(nil)
		encode = append(encode, checksum[:2]...)

		if !bytes.Equal(encode, b) {
			return fmt.Errorf("invalid public key, checksum mismatch")
		}

		if err := (&sr25519.PublicKey{}).Decode(b[1:33]); err == nil {
			if prompt {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(),
					fmt.Sprintf("sr25519 public key for network %s is valid", network),
				); err != nil {
					return fmt.Errorf("failed to write to output: %w", err)
				}
			}
			return nil
		}

		if err := (&ed25519.PublicKey{}).Decode(b[1:33]); err == nil {
			if prompt {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(),
					fmt.Sprintf("ed25519 public key for network %s is valid", network),
				); err != nil {
					return fmt.Errorf("failed to write to output: %w", err)
				}
			}
			return nil
		}

		return fmt.Errorf("invalid public key")
	default:
		return fmt.Errorf("invalid key length of %d bytes, expected 32, 64 (for prv key) or 35 (for pub key)", len(b))
	}

	return nil
}
