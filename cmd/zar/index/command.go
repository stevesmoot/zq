package index

import (
	"flag"

	"github.com/brimsec/zq/archive"
	"github.com/brimsec/zq/cmd/zar/root"
	"github.com/mccanne/charm"
)

var Index = &charm.Spec{
	Name:  "index",
	Usage: "index [options]",
	Short: "creates index files for bzng files",
	Long: `
TBD
`,
	New: New,
}

func init() {
	root.Zar.Add(Index)
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
	return archive.IndexDirTree(c.dir)
}
