package run

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"syscall"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/ChainSafe/gossamer/lib/crypto"
	"github.com/ChainSafe/gossamer/lib/crypto/ed25519"
	"github.com/ChainSafe/gossamer/lib/crypto/sr25519"
	"github.com/kubetrail/dotkey/pkg/flags"
	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/term"
)

var ss58Prefix = []byte("SS58PRE")

func Gen(cmd *cobra.Command, args []string) error {
	_ = viper.BindPFlag(flags.UsePassphrase, cmd.Flags().Lookup(flags.UsePassphrase))
	_ = viper.BindPFlag(flags.SkipMnemonicValidation, cmd.Flags().Lookup(flags.SkipMnemonicValidation))
	_ = viper.BindPFlag(flags.InputHexSeed, cmd.Flags().Lookup(flags.InputHexSeed))
	_ = viper.BindPFlag(flags.DerivationPath, cmd.Flags().Lookup(flags.DerivationPath))
	_ = viper.BindPFlag(flags.Network, cmd.Flags().Lookup(flags.Network))
	_ = viper.BindPFlag(flags.Scheme, cmd.Flags().Lookup(flags.Scheme))

	derivationPath := viper.GetString(flags.DerivationPath)
	usePassphrase := viper.GetBool(flags.UsePassphrase)
	skipMnemonicValidation := viper.GetBool(flags.SkipMnemonicValidation)
	inputHexSeed := viper.GetBool(flags.InputHexSeed)
	network := viper.GetString(flags.Network)
	scheme := viper.GetString(flags.Scheme)

	derivationPath = strings.ReplaceAll(
		strings.ToLower(derivationPath), "h", "'")

	prompt, err := getPromptStatus()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	var passphrase []byte
	var seed []byte

	if inputHexSeed && usePassphrase {
		return fmt.Errorf("cannot use passphrase when entering seed")
	}

	if inputHexSeed && skipMnemonicValidation {
		return fmt.Errorf("dont use --skip-mnemonic-validation when entering seed")
	}

	if !inputHexSeed {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter mnemonic: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}

		inputReader := bufio.NewReader(cmd.InOrStdin())
		mnemonic, err := inputReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read mnemonic from input: %w", err)
		}
		mnemonic = strings.Trim(mnemonic, "\n")

		if !skipMnemonicValidation && !bip39.IsMnemonicValid(mnemonic) {
			return fmt.Errorf("mnemonic is invalid or please use --skip-mnemonic-validation flag")
		}

		if usePassphrase {
			if prompt {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter secret passphrase: "); err != nil {
					return fmt.Errorf("failed to write to output: %w", err)
				}
			}

			passphrase, err = term.ReadPassword(syscall.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read secret passphrase from input: %w", err)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter secret passphrase again: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}

			passphraseConfirm, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read secret passphrase from input: %w", err)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}

			if !bytes.Equal(passphrase, passphraseConfirm) {
				return fmt.Errorf("passphrases do not match")
			}
		}

		if !skipMnemonicValidation {
			seedArray, err := schnorrkel.SeedFromMnemonic(mnemonic, string(passphrase))
			if err != nil {
				return fmt.Errorf("failed to generate seed from mnemonic: %w", err)
			}

			seed = seedArray[:]
		} else {
			seed = bip39.NewSeed(mnemonic, string(passphrase))
		}
	} else {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter seed in hex: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}

		inputReader := bufio.NewReader(cmd.InOrStdin())
		hexSeed, err := inputReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read mnemonic from input: %w", err)
		}
		hexSeed = strings.Trim(hexSeed, "\n")

		seed, err = hex.DecodeString(hexSeed)
		if err != nil {
			return fmt.Errorf("invalid seed: %w", err)
		}
	}

	var pair crypto.Keypair

	switch strings.ToLower(scheme) {
	case "ed25519":
		if len(seed) < ed25519.SeedLength {
			return fmt.Errorf("invalid seed length %d, need %d", len(seed), ed25519.SeedLength)
		}
		seed = seed[:ed25519.SeedLength]
		pair, err = ed25519.NewKeypairFromSeed(seed)
		if err != nil {
			return fmt.Errorf("failed to generate ed25519 keypair: %w", err)
		}
	case "sr25519":
		if len(seed) < sr25519.SeedLength {
			return fmt.Errorf("invalid seed length %d, need %d", len(seed), sr25519.SeedLength)
		}
		seed = seed[:sr25519.SeedLength]
		pair, err = sr25519.NewKeypairFromSeed(seed)
		if err != nil {
			return fmt.Errorf("failed to generate sr25519 keypair: %w", err)
		}
	default:
		return fmt.Errorf("invalid crypto scheme, try either sr25519 or ed25519")
	}

	if err := populateRegistry(); err != nil {
		return fmt.Errorf("internal error, failed to pupulate network registry: %w", err)
	}

	// encode network and checksum
	encode := pair.Public().Encode()

	if nw, ok := networks[strings.ToLower(network)]; !ok {
		if _, err := hex.DecodeString(network); err != nil {
			return fmt.Errorf("invalid network %s, pl. try substrate", network)
		}
	} else {
		network = nw
	}

	netByte, err := hex.DecodeString(network)
	if err != nil {
		return fmt.Errorf("failed to decode network as hex string: %w", err)
	}
	if len(netByte) != 1 {
		return fmt.Errorf("invalid network, needs to be just one byte")
	}
	encode = append(netByte, encode...)

	hash, err := blake2b.New(64, nil)
	if err != nil {
		return fmt.Errorf("failed to generate blake2b hash func: %w", err)
	}
	if _, err := hash.Write(append(ss58Prefix, encode...)); err != nil {
		return fmt.Errorf("failed to hash data: %w", err)
	}
	checksum := hash.Sum(nil)
	encode = append(encode, checksum[:2]...)

	outPub := base58.Encode(encode)
	outPrv := base58.Encode(pair.Private().Encode())

	if prompt {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "pub:", outPub); err != nil {
			return fmt.Errorf("failed to write key to output: %w", err)
		}

		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "prv:", outPrv); err != nil {
			return fmt.Errorf("failed to write key to output: %w", err)
		}

		return nil
	}

	jb, err := json.Marshal(
		struct {
			Prv string `json:"prv,omitempty"`
			Pub string `json:"pub,omitempty"`
		}{
			Prv: outPrv,
			Pub: outPub,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to serialize output: %w", err)
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(jb)); err != nil {
		return fmt.Errorf("failed to write key to output: %w", err)
	}

	return nil
}
