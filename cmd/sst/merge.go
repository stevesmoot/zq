package cmd

import (
	"bytes"
	"errors"
	"flag"

	"github.com/RoaringBitmap/roaring"

	"github.com/brimsec/zq/pkg/sst"
	"github.com/mccanne/charm"
)

var Merge = &charm.Spec{
	Name:  "merge",
	Usage: "merge [ -f framesize ] -o file file1, file2, ...  ",
	Short: "merge two or sst files into the output file",
	Long: `
The merge command takes two or more sst files as input and merges them into
a new file, as specified by the -o argument, merging the files while preserving
the lexicographic order of the keys and performing a bitwise OR of the roaring
bitmap values.`,
	New: newMergeCommand,
}

type MergeCommand struct {
	*Command
	oflag     string
	framesize int
}

func newMergeCommand(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &MergeCommand{Command: parent.(*Command)}
	f.IntVar(&c.framesize, "f", 32*1024, "minimum frame size used in the output sst file")
	f.StringVar(&c.oflag, "o", "", "output file name")
	return c, nil
}

func combine(a, b []byte) []byte {
	//XXX there's surely a better way to do this
	A := roaring.New()
	_, err := A.ReadFrom(bytes.NewBuffer(a))
	if err != nil {
		return nil
	}
	B := roaring.New()
	_, err = B.ReadFrom(bytes.NewBuffer(b))
	if err != nil {
		return nil
	}
	X := roaring.Or(A, B)
	buf := new(bytes.Buffer)
	_, err = X.WriteTo(buf)
	return buf.Bytes()
}

func (c *MergeCommand) Run(args []string) error {
	if len(args) < 2 {
		return errors.New("must specify at least two input files")
	}
	if c.oflag == "" {
		return errors.New("must specify output file with -o")
	}
	var files []sst.Stream
	for _, fname := range args {
		files = append(files, sst.NewReader(fname))
	}
	combiner := sst.NewCombiner(files, combine)
	defer combiner.Close()
	writer, err := sst.NewWriter(c.oflag, c.framesize, 0)
	if err != nil {
		return err
	}
	return sst.Copy(writer, combiner)
}
