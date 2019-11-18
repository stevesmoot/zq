package zjson

import (
	"bufio"
	"encoding/json"
	"io"

	"github.com/mccanne/zq/pkg/zeek"
	"github.com/mccanne/zq/pkg/zson"
	"github.com/mccanne/zq/pkg/zval"
)

type Column struct {
	Name string      `json:"name"`
	Type interface{} `json:"type"`
}

type Value struct {
	Id   int         `json:"id"`
	Type interface{} `json:"type,omitempty"`
	Body interface{} `json:"value"`
}

type Writer struct {
	writer      *bufio.Writer
	closer      io.Closer
	descriptors map[int]struct{}
}

func NewWriter(w io.WriteCloser) *Writer {
	return &Writer{
		writer:      bufio.NewWriter(w),
		closer:      w,
		descriptors: make(map[int]struct{}),
	}
}

func (w *Writer) Close() error {
	if err := w.writer.Flush(); err != nil {
		return err
	}
	return w.closer.Close()
}

func (w *Writer) Write(r *zson.Record) error {
	id := r.Descriptor.ID
	_, ok := w.descriptors[id]
	var typ interface{}
	if !ok {
		var err error
		w.descriptors[id] = struct{}{}
		typ, err = w.encodeType(r.Descriptor.Type)
		if err != nil {
			return err
		}
	}
	body, err := w.encodeContainer(r.Raw)
	if err != nil {
		return err
	}
	v := Value{
		Id:   id,
		Type: typ,
		Body: body,
	}
	b, err := json.Marshal(&v)
	if err != nil {
		return err
	}
	_, err = w.writer.Write(b)
	if err != nil {
		return err
	}
	return w.write("\n")
}

func (w *Writer) write(s string) error {
	_, err := w.writer.Write([]byte(s))
	return err
}

func (w *Writer) encodeContainer(val []byte) ([]interface{}, error) {
	var body []interface{}
	if len(val) > 0 {
		for it := zval.Iter(val); !it.Done(); {
			v, container, err := it.Next()
			if err != nil {
				return nil, err
			}
			if container {
				child, err := w.encodeContainer(v)
				if err != nil {
					return nil, err
				}
				body = append(body, child)
			} else {
				body = append(body, string(v))
			}
		}
	}
	return body, nil
}

func (w *Writer) encodeType(typ *zeek.TypeRecord) (interface{}, error) {
	var columns []interface{}
	for _, c := range typ.Columns {
		childRec, ok := c.Type.(*zeek.TypeRecord)
		var typ interface{}
		if ok {
			var err error
			typ, err = w.encodeType(childRec)
			if err != nil {
				return nil, err
			}
		} else {
			typ = c.Type.String()
		}
		columns = append(columns, Column{Name: c.Name, Type: typ})
	}
	return columns, nil
}
