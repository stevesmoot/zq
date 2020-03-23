package cmd

import (
	"bytes"
	"flag"
	"fmt"
	"io"

	"github.com/brimsec/zq/pkg/sst"
	"github.com/mccanne/charm"
)

var Dump = &charm.Spec{
	Name:  "dump",
	Usage: "dump [ -i file ] [-l level] [-k key]",
	Short: "dump all the frames",
	Long: `
The dump command prints out the keys and offsets of a frame in an sst file,
or the keys within a frame indicated by the key parameter.`,
	New: newDumpCommand,
}

type DumpCommand struct {
	*Command
	iflag string
	level int
	kflag string
	vflag bool
}

func newDumpCommand(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &DumpCommand{Command: parent.(*Command)}
	f.StringVar(&c.iflag, "i", "sst", "input file name")
	f.StringVar(&c.kflag, "k", "", "key of frame to dump")
	f.IntVar(&c.level, "l", 0, "sst level to dump")
	f.BoolVar(&c.vflag, "v", false, "dump all keys")
	return c, nil
}

func (c *DumpCommand) dumpBase(key, frame []byte) {
	for len(frame) > 0 {
		pair, n := sst.DecodePair(frame)
		if pair.Value == nil {
			return
		}
		fmt.Printf("%s (%d)\n", string(pair.Key), len(pair.Value))
		frame = frame[n:]
	}
}

func (c *DumpCommand) dumpIndexFrame(key, frame []byte) {
	for len(frame) > 0 {
		k, off, n := sst.DecodeIndex(frame)
		if k == nil {
			return
		}
		fmt.Printf("%s %d\n", string(k), off)
		frame = frame[n:]
	}
}

func (c *DumpCommand) Run(args []string) error {
	reader := sst.NewFrameReader(c.iflag, c.level)
	defer reader.Close()
	if err := reader.Open(); err != nil {
		return err
	}
	off := int64(sst.FileHeaderLen)
	var key []byte
	if c.kflag != "" {
		key = []byte(c.kflag)
	}
	for {
		frame, err := reader.ReadFrameAt(off)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if frame == nil {
			break
		}
		firstKey := sst.FirstKey(frame)
		if key == nil && !c.vflag {
			fmt.Printf("%s %d %d\n", string(firstKey), off, len(frame))
		} else if bytes.Equal(key, firstKey) || c.vflag {
			// dump the frame's keys and exists
			if c.level == 0 {
				c.dumpBase(key, frame)
			} else {
				c.dumpIndexFrame(key, frame)
			}
			if !c.vflag {
				return nil
			}
		}
		off += int64(len(frame) + sst.FrameHeaderLen)
	}
	return nil
}
