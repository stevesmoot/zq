package bzngio

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mccanne/zq/pkg/nano"
	"github.com/mccanne/zq/zng"
	"github.com/mccanne/zq/zng/resolver"
)

type Index []Mark

type Mark struct {
	Ts     nano.Ts
	Offset int64
}

type IndexReader struct {
	*Reader
	Index Index
	ts    nano.Ts
	count int
}

const stride = 5000 // XXX

func NewIndexReader(reader io.Reader, zctx *resolver.Context) *IndexReader {
	return &IndexReader{
		Reader: NewReader(reader, zctx),
	}
}

func (i *IndexReader) Read() (*zng.Record, error) {
	position := i.Reader.peeker.Position()
	rec, err := i.Reader.Read()
	if err != nil {
		return nil, err
	}
	i.count++
	if i.count >= stride {
		ts := rec.Ts
		if ts > i.ts {
			i.count = 0
			i.ts = ts
			i.Index = append(i.Index, Mark{ts, int64(position)})
		}
	}
	return rec, nil
}

type RangeReader struct {
	*Reader
	end nano.Ts
}

func fastforward(ts nano.Ts, index Index) int64 {
	var off int64
	for _, mark := range index {
		if mark.Ts > ts {
			return off
		}
		off = mark.Offset
	}
	return off
}

func NewRangeReader(f *os.File, zctx *resolver.Context, index Index, span nano.Span) (*RangeReader, error) {
	off := fastforward(span.Ts, index)
	newoff, err := f.Seek(off, 0)
	if err != nil {
		return nil, err
	}
	fmt.Println("SEEK", off, newoff)
	if newoff != off {
		return nil, errors.New("file truncated") //XXX
	}
	return &RangeReader{
		Reader: NewReader(f, zctx),
		end:    span.End(),
	}, nil
}

func (i *RangeReader) Read() (*zng.Record, error) {
	rec, err := i.Reader.Read()
	if err != nil {
		fmt.Println("RANGE ERR", err)
		return nil, err
	}
	fmt.Println("RANGE READ", rec)
	if rec.Ts > i.end {
		rec = nil
	}
	return rec, nil
}
