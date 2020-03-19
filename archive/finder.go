package archive

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/brimsec/zq/pkg/sst"
)

//XXX this is a test searches for IP addresses
func Find(dir string, pattern []byte) ([]string, error) {
	nerr := 0
	//XXX this should be parallelized with some locking presuming a little
	// parallelism won't mess up the file system assumptions
	var hits []string
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
			hit, err := SearchFile(path, pattern)
			if err != nil {
				fmt.Printf("%s: %s\n", path, err)
				nerr++
				if nerr > 10 {
					//XXX
					return errors.New("stopping after too many errors...")
				}
			}
			if hit {
				hits = append(hits, path)
			}
		}
		return nil
	})
	return hits, err
}

func SearchFile(path string, pattern []byte) (bool, error) {
	subdir := path + zarExt
	sstName := "sst:type:ip"
	sstPath := filepath.Join(subdir, sstName)
	finder, err := sst.NewFinder(sstPath)
	if err != nil {
		return false, err
	}
	v, err := finder.Lookup(pattern)
	return v != nil, err
}
