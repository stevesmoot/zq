package cmd

import (
	"errors"
	"flag"
	"fmt"

	"github.com/RoaringBitmap/roaring"

	"github.com/brimsec/zq/pkg/sst"
	"github.com/mccanne/charm"
)

var Lookup = &charm.Spec{
	Name:  "lookup",
	Usage: "lookup [ -i file ] key",
	Short: "lookup a key in an sst file and print value as hex bytes",
	Long: `
The lookup command uses the index files of an sst hierarchy to locate the
specified key in the base sst file and displays the value as bytes.`,
	New: newLookupCommand,
}

type LookupCommand struct {
	*Command
	iflag string
}

func newLookupCommand(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &LookupCommand{Command: parent.(*Command)}
	f.StringVar(&c.iflag, "i", "sst", "input file name")
	return c, nil
}

func (c *LookupCommand) Run(args []string) error {
	if len(args) != 1 {
		return errors.New("must specify a key")
	}
	finder, err := sst.NewFinder(c.iflag)
	if err != nil {
		return err
	}
	defer finder.Close()
	val, err := finder.Lookup([]byte(args[0]))
	if err != nil {
		return err
	}
	if val == nil {
		fmt.Println("not found")
	} else {
		bitmap := roaring.New()
		_, err := bitmap.FromBuffer(val)
		if err != nil {
			return err
		}
		fmt.Println(bitmap.String())
	}
	return nil
}
