package run

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// https://raw.githubusercontent.com/paritytech/ss58-registry/main/ss58-registry.json
//go:embed ss58-registry.json
var registryData []byte

// https://github.com/paritytech/ss58-registry/blob/main/ss58-registry.json
var networks map[string]string

func populateRegistry() error {
	networks = make(map[string]string)
	registry := &Registry{}
	if err := json.Unmarshal(registryData, registry); err != nil {
		return fmt.Errorf("failed to unmarshal registry data: %w", err)
	}

	for _, network := range registry.Networks {
		networks[strings.ToLower(network.Network)] = hex.EncodeToString([]byte{byte(network.Prefix)})
	}

	return nil
}

type Registry struct {
	Specification string    `json:"specification"`
	Schema        Schema    `json:"schema"`
	Networks      []Network `json:"registry"`
}

type Schema struct {
	Prefix          string `json:"prefix"`
	Network         string `json:"network"`
	DisplayName     string `json:"displayName"`
	Symbols         string `json:"symbols"`
	Decimals        string `json:"decimals"`
	StandardAccount string `json:"standardAccount"`
	Website         string `json:"website"`
}

type Network struct {
	Prefix          int      `json:"prefix"`
	Network         string   `json:"network"`
	DisplayName     string   `json:"displayName"`
	Symbols         []string `json:"symbols"`
	Decimals        []int    `json:"decimals"`
	StandardAccount string   `json:"standardAccount"`
	Website         string   `json:"website"`
}
