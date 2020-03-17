package index

import (
	"errors"
	"flag"
	"fmt"
	"net"

	"github.com/brimsec/zq/archive"
	"github.com/brimsec/zq/cmd/zar/root"
	"github.com/mccanne/charm"
)

var Find = &charm.Spec{
	Name:  "find",
	Usage: "find [options]",
	Short: "find looks throught index files for bzng files and displays matches",
	Long: `
TBD
`,
	New: New,
}

func init() {
	root.Zar.Add(Find)
}

type Command struct {
	*root.Command
	dir string
}

func New(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &Command{Command: parent.(*root.Command)}
	f.StringVar(&c.dir, "d", ".", "directory to descend")
	return c, nil
}

func (c *Command) Run(args []string) error {
	if len(args) != 1 {
		return errors.New("zar find: no search pattern provided")
	}
	//XXX presume ip address
	pattern := net.ParseIP(args[0])
	if pattern == nil {
		//XXX
		return errors.New("zar find: invalid IP address: " + args[0])
	}
	hits, err := archive.Find(c.dir, pattern)
	if err != nil {
		return err
	}
	//XX should stream hits as they are found instead of collecting them
	// all up them dumping the slice to stdout
	for _, hit := range hits {
		fmt.Println(hit)
	}
	return nil
}
