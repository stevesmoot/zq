package archive

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/brimsec/zq/pkg/sst"
	"github.com/brimsec/zq/zio/detector"
	"github.com/brimsec/zq/zng/resolver"
)

//XXX this is a test searches for IP addresses
func FindDirTree(dir string, pattern []byte) ([]string, error) {
	nerr := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("%q: %v", path, err)
		}
		name := info.Name()
		if info.IsDir() {
			if filepath.Ext(name) == zarExt {
				//XXX need to merge into or replace existing index
				return filepath.SkipDir
			}
			// descend...
			return nil
		}
		if filepath.Ext(name) == ".bzng" {
			err = IndexLogFile(path)
			if err != nil {
				fmt.Printf("%s: %s\n", path, err)
				nerr++
				if nerr > 10 {
					//XXX
					return errors.New("stopping after too many errors...")
				}
			}
			// drop through and continue
		}
		return nil
	})
	return err
}

func IndexLogFile(path string) error {
	subdir := path + zarExt
	sstName := "sst:type:ip"
	sstPath := filepath.Join(subdir, sstName)
	// XXX remove without warning, should have force flag
	sst.Remove(sstPath)

	fmt.Printf("%s: indexing as %s\n", path, sstPath)

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader, err := detector.LookupReader("bzng", file, resolver.NewContext())
	if err != nil {
		return err
	}
	table, err := indexTypeIP(reader)
	if err != nil {
		return err
	}
	if table.Size() == 0 {
		//XXX
		return errors.New("nothing to index")
	}
	// make subdirectory for index if it doesn't exist
	if err := os.Mkdir(subdir, 0755); err != nil {
		if !os.IsExist(err) {
			return err
		}
	}
	framesize := 32 * 1024
	//XXX for now specify value size of 1, where we will put a dummy 0 byte.
	// we should change the implementation to allow key-only SSTs.
	writer, err := sst.NewWriter(sstPath, framesize, 1)
	if err != nil {
		return err
	}
	defer writer.Close()
	return sst.Copy(writer, table)
}
