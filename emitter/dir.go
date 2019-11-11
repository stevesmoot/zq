package emitter

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mccanne/zq/pkg/zsio/zeek"
	"github.com/mccanne/zq/pkg/zson"
)

var (
	ErrNoPath = errors.New("no _path field in column 1 of tuple")
)

// Dir implements the Writer interface and sends all log lines with the
// same descriptor to a file named <prefix><path>.<ext> in the directory indicated,
// where <prefix> and <ext> are specificied and <path> is determined by the
// _path field in the boom descriptor.  If more than one path exists with
// different descriptors, the later tuples are ignored.
type Dir struct {
	dir     string
	prefix  string
	ext     string
	stderr  io.Writer
	writers map[*zson.Descriptor]zson.WriteCloser
	paths   map[string]int
}

func NewDir(dir, prefix, ext string, stderr io.Writer) (*Dir, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &Dir{
		dir:     dir,
		prefix:  prefix,
		ext:     ext,
		stderr:  stderr,
		writers: make(map[*zson.Descriptor]zson.WriteCloser),
		paths:   make(map[string]int),
	}, nil
}

func (d *Dir) Write(r *zson.Record) error {
	out, err := d.lookupOutput(r)
	if err != nil {
		return err
	}
	return out.Write(r)
}

type blackhole struct{}

func (b *blackhole) Write(r *zson.Record) error {
	return nil
}

func (b *blackhole) Close() error {
	return nil
}

func (d *Dir) lookupOutput(rec *zson.Record) (zson.WriteCloser, error) {
	descriptor := rec.Descriptor
	w, ok := d.writers[descriptor]
	if ok {
		return w, nil
	}
	file, fname, err := d.newFile(rec)
	if os.IsNotExist(err) {
		//XXX fix Phil's error message
		// warn that file exists
		warning := fmt.Sprintf("%s: file exists (blocking writes to this file, but continuing)\n", fname)
		d.stderr.Write([]byte(warning))
		// block future writes to this descriptor since file exists
		d.writers[descriptor] = &blackhole{}
	} else if err != nil {
		return nil, err
	}
	w = zeek.NewWriter(file)
	d.writers[descriptor] = w
	return w, nil
}

// filename returns the name of the file for the specified path. This handles
// the case of two tds one _path, adding a # in the filename for every _path that
// has more than one td.
func (p *Dir) filename(path string) string {
	filename := p.prefix + path
	if p.paths[path]++; p.paths[path] > 1 {
		filename += fmt.Sprintf("-%d", p.paths[path])
	}
	filename += p.ext
	return filepath.Join(p.dir, filename)
}

func (p *Dir) newFile(rec *zson.Record) (*os.File, string, error) {
	// get path name from descriptor.  the td at column 0
	// has already been stripped out.
	i, ok := rec.Descriptor.ColumnOfField("_path")
	if !ok {
		return nil, "", ErrNoPath
	}
	path := string(rec.Slice(i))
	filename := p.filename(path)
	flags := os.O_WRONLY | os.O_CREATE
	file, err := os.OpenFile(filename, flags, 0644)
	if err != nil {
		if err == os.ErrExist {
			// The files exists and we're not going to overwrite it.
			// Return nil for the file with no error indicating that
			// we should track this path but block all such tuples.
			return nil, filename, nil
		}
		return nil, filename, err
	}
	return file, filename, nil
}

func (p *Dir) Close() error {
	var cerr error
	for _, w := range p.writers {
		if err := w.Close(); err != nil {
			cerr = err
		}
	}
	return cerr
}