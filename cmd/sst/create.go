package cmd

import (
	"errors"
	"flag"
	"os"

	"github.com/brimsec/zq/pkg/sst"
	"github.com/mccanne/charm"
)

var Create = &charm.Spec{
	Name:  "create",
	Usage: "create [-f framesize] [ -o file ] file",
	Short: "generate an sst file from a tsv file",
	Long: `
The create command generates an sst containing string keys and binary values.
Each line in the input file constists of a text field terminated with a colon
then a byte string represented as sequence of bytes encoded as a two-character
hex value.  The value is teminated with a newline.  A nil value is represented
with no characters (i.e., string key, colon, then newline)`
	New: newCreateCommand,
}

type CreateCommand struct {
	*Command
	framesize int
	oflag     string
	iflag     string
}

func newCreateCommand(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &CreateCommand{Command: parent.(*Command)}
	f.IntVar(&c.framesize, "f", 32*1024, "minimum frame size used in SST file")
	f.StringVar(&c.oflag, "o", "sst", "output file name")
	f.StringVar(&c.iflag, "i", "", "input file name")
	return c, nil
}

func (c *CreateCommand) Run(args []string) error {
	if c.iflag == "" {
		return errors.New("must specify an input file with -i")
	}
	in, err := os.Open(c.iflag)
	if err != nil {
		return err
	}
	defer in.Close()
	table := NewTable()
	if err := table.Scan(in); err != nil {
		return err
	}
	writer, err := sst.NewWriter(c.oflag, c.framesize, 0)
	if err != nil {
		return err
	}
	return sst.Copy(writer, table)
}
