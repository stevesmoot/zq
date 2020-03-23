package cmd

import (
	"flag"

	"github.com/mccanne/charm"
)

var Sst = &charm.Spec{
	Name:  "sst",
	Usage: "sst <command> [options] [arguments...]",
	Short: "use sst to test/debug boom sst files",
	Long: `
sst is command-line utility useful for debugging the sst packaging and
interrogating sst files that are corrected by a client of sst, e.g.,
to debug the indexer in boom.`,
	New: func(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
		return &Command{}, nil
	},
}

func init() {
	Sst.Add(charm.Help)
	Sst.Add(Create)
	Sst.Add(Lookup)
	Sst.Add(Merge)
	Sst.Add(Dump)
}

type Command struct{}

func (c *Command) Run(args []string) error {
	return charm.ErrNoRun
}
