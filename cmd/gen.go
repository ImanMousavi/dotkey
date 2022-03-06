/*
Copyright © 2022 kubetrail.io authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/kubetrail/dotkey/pkg/flags"
	"github.com/kubetrail/dotkey/pkg/run"
	"github.com/spf13/cobra"
)

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate key from mnemonic",
	Long: `This command generates private/public keys
from mnemonic and optional secret passphrase per BIP-32 spec.

The keys are generated based on a chain derivation path
Path     |   Remark
---------|--------------------------------------------------------------
m        |   Master key (aka root key)
m/0      |   First child of master key
m/0'     |   First hardened child of master key
m/0/0    |   First child of first child of master key
m/0'/0   |   First child of first hardened child of master key
m/0/0'   |   First hardened child of first child of master key
m/0'/0'  |   First hardened child of first hardened child of master key'

Network values can be one of:
  polkadot BareSr25519 kusama BareEd25519 katalchain astar bifrost 
  edgeware karura reynolds acala laminar polymesh integritee totem 
  synesthesia kulupu dark darwinia geek stafi dock-testnet dock-mainnet 
  shift zero zero-alphaville jupiter kabocha subsocial cord phala 
  litentry robonomics datahighway ares vln centrifuge nodle kilt 
  mathchain mathchain-testnet poli substrate BareSecp256k1 chainx 
  uniarts reserved46 reserved47 neatcoin picasso composable oak KICO 
  DICO xxnetwork hydradx aventus crust genshiro equilibrium sora 
  zeitgeist manta calamari polkadex polkasmith polkafoundry 
  origintrail-parachain pontem-network heiko integritee-incognito 
  clover litmus altair parallel social-network quartz_mainnet 
  pioneer_network sora_kusama_para efinity moonbeam moonriver ajuna 
  kapex interlay kintsugi subspace_testnet subspace basilisk cess-testnet 
  cess contextfree

`,
	RunE: run.Gen,
}

func init() {
	rootCmd.AddCommand(genCmd)
	f := genCmd.Flags()

	f.String(flags.DerivationPath, "m/44'/501'/0'/0'", "Chain derivation path (hardened only)")
	f.Bool(flags.UsePassphrase, false, "Prompt for secret passphrase")
	f.Bool(flags.InputHexSeed, false, "Treat input as hex seed instead of mnemonic")
	f.Bool(flags.SkipMnemonicValidation, false, "Skip mnemonic validation")
	f.String(flags.Network, "substrate", "Network name")
	f.String(flags.Scheme, "sr25519", "Cryptographic scheme: ed25519, sr25519, ecdsa")
}
