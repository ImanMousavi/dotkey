package run

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func NetworkList(cmd *cobra.Command, args []string) error {
	if err := populateRegistry(); err != nil {
		return fmt.Errorf("failed to pupulate network list: %w", err)
	}
	table := tablewriter.NewWriter(cmd.OutOrStdout())
	table.SetHeader([]string{"Prefix", "Name"})
	table.SetBorder(false)
	table.SetColumnSeparator(" ")

	list := networkList{}
	for k, v := range networks {
		d, err := hex.DecodeString(v)
		if err != nil || len(d) != 1 {
			return fmt.Errorf("failed to decode network prefix: %w", err)
		}

		list = append(
			list,
			Network{
				Prefix:          int(d[0]),
				Network:         k,
				DisplayName:     v,
				Symbols:         nil,
				Decimals:        nil,
				StandardAccount: "",
				Website:         "",
			},
		)
	}

	sort.Sort(&list)
	for _, network := range list {
		table.Append([]string{fmt.Sprintf("0x%s", network.DisplayName), network.Network})
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(),
		"https://github.com/paritytech/ss58-registry/blob/main/ss58-registry.json"); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	table.Render()

	return nil
}

type networkList []Network

func (g networkList) Len() int {
	return len(g)
}

func (g networkList) Less(i, j int) bool {
	return g[i].Prefix < g[j].Prefix
}

func (g networkList) Swap(i, j int) {
	g[i], g[j] = g[j], g[i]
}
