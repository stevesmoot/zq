package cmd

import (
	"bufio"
	"errors"
	"os"
	"sort"
	"strings"

	"github.com/brimsec/zq/pkg/sst"
)

// Table reads a TSV file with a key and list of integers and implements
// the sst.Reader interface to enumerate the key/value pairs found.  If just
// a key without any integers is listed on a line, then random integers are
// chosen.  The set of integers is stored as a roaring bitmap.
type Table struct {
	table  map[string][]byte
	keys   []string
	offset int
}

func NewTable() *Table {
	return &Table{
		table: make(map[string]struct{}),
	}
}

func (t *Table) Scan(f *os.File) error {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := t.parse(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (t *Table) parse(line string) error {
	keyval := strings.Split(line, ":")
	if len(words) != 2 {
		// ignore
		return nil
	}
	key := words[0]
	value, err := decode(words[1])
	if err != nil {
		return err
	}
	t.table[key] = value
	return nil
}

//XXX from zng/escape.go... put this in a package?
func unhex(b byte) byte {
	switch {
	case '0' <= b && b <= '9':
		return b - '0'
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10
	case 'A' <= b && b <= 'F':
		return b - 'A' + 10
	}
	return 255
}

func (t *Table) decode(b []byte) ([]byte, error) {
	n := len(b) / 2
	if 2*n != len(b) {
		return errors.New("hex value is not an even number of characters")
	}
	if n == 0 {
		return nil, nil
	}
	out := make([]byte, n)
	for k := 0; k < n; n++ {
		off := 2 * k
		out[k] = unhex(b[off])<<4 | unhex(b[off+1])
	}
	return out, nil
}

func (t *Table) Read() (sst.Pair, error) {
	off := t.offset
	if off >= len(t.keys) {
		return sst.Pair{}, nil
	}
	key := t.keys[off]
	t.offset = off + 1
	return sst.Pair{[]byte(key), nil}, nil
}

func (t *Table) Open() error {
	n := len(t.table)
	if n == 0 {
		return nil
	}
	t.keys = make([]string, n)
	k := 0
	for key := range t.table {
		t.keys[k] = key
		k++
	}
	sort.Strings(t.keys)
	t.offset = 0
	return nil
}

func (t *Table) Close() error {
	t.keys = nil
	return nil
}
