package resolver

import (
	"fmt"

	"github.com/mccanne/zq/zcode"
	"github.com/mccanne/zq/zng"
)

type Encoder struct {
	table   []zng.Type
	zctx    *Context
	encoded map[int]struct{}
}

func NewEncoder() *Encoder {
	return &Encoder{
		zctx:    NewContext(),
		encoded: make(map[int]struct{}),
	}
}

func (e *Encoder) Lookup(external zng.Type) zng.Type {
	id := external.ID()
	if id >= 0 && id < len(e.table) {
		return e.table[id]
	}
	return nil
}

func (e *Encoder) enter(id int, typ zng.Type) {
	if id >= len(e.table) {
		new := make([]zng.Type, id+1)
		copy(new, e.table)
		e.table = new
	}
	e.table[id] = typ
}

func (e *Encoder) isEncoded(typ zng.Type) bool {
	id := typ.ID()
	if _, ok := e.encoded[id]; ok {
		return true
	}
	e.encoded[id] = struct{}{}
	return false
}

// Encode takes a type from outside this context and constructs a type from
// inside this context and emits ZNG typedefs for any type needed to construct
// the new type into the buffer provided.
func (e *Encoder) Encode(dst []byte, external zng.Type) ([]byte, zng.Type) {
	dst, typ := e.encodeType(dst, external)
	e.enter(external.ID(), typ)
	return dst, typ
}

func (e *Encoder) encodeType(dst []byte, ext zng.Type) ([]byte, zng.Type) {
	id := ext.ID()
	if id < zng.IdTypeDef {
		return dst, ext
	}
	switch ext := ext.(type) {
	default:
		//XXX
		panic(fmt.Sprintf("bzng cannot encode type: %s", ext))
	case *zng.TypeRecord:
		return e.encodeTypeRecord(dst, ext)
	case *zng.TypeSet:
		return e.encodeTypeSet(dst, ext)
	case *zng.TypeVector:
		return e.encodeTypeVector(dst, ext)
	}
}

func (e *Encoder) encodeTypeRecord(dst []byte, ext *zng.TypeRecord) ([]byte, zng.Type) {
	var columns []zng.Column
	for _, col := range ext.Columns {
		var child zng.Type
		dst, child = e.encodeType(dst, col.Type)
		columns = append(columns, zng.NewColumn(col.Name, child))
	}
	typ := e.zctx.LookupTypeRecord(columns)
	if e.isEncoded(typ) {
		return dst, typ
	}
	return serializeTypeRecord(dst, columns), typ
}

func serializeTypeRecord(dst []byte, columns []zng.Column) []byte {
	dst = append(dst, zng.TypeDefRecord)
	dst = zcode.AppendUvarint(dst, uint64(len(columns)))
	for _, col := range columns {
		name := []byte(col.Name)
		dst = zcode.AppendUvarint(dst, uint64(len(name)))
		dst = append(dst, name...)
		dst = zcode.AppendUvarint(dst, uint64(col.Type.ID()))
	}
	return dst
}

func (e *Encoder) encodeTypeSet(dst []byte, ext *zng.TypeSet) ([]byte, zng.Type) {
	var inner zng.Type
	dst, inner = e.encodeType(dst, ext.InnerType)
	typ := e.zctx.LookupTypeSet(inner)
	if e.isEncoded(typ) {
		return dst, typ
	}
	return serializeTypeSet(dst, typ.InnerType), typ
}

func serializeTypeSet(dst []byte, inner zng.Type) []byte {
	dst = append(dst, zng.TypeDefSet)
	dst = zcode.AppendUvarint(dst, 1)
	return zcode.AppendUvarint(dst, uint64(inner.ID()))
}

func (e *Encoder) encodeTypeVector(dst []byte, ext *zng.TypeVector) ([]byte, zng.Type) {
	var inner zng.Type
	dst, inner = e.encodeType(dst, ext.Type)
	typ := e.zctx.LookupTypeVector(inner)
	if e.isEncoded(typ) {
		return dst, typ
	}
	return serializeTypeVector(dst, inner), typ
}

func serializeTypeVector(dst []byte, inner zng.Type) []byte {
	dst = append(dst, zng.TypeDefArray)
	return zcode.AppendUvarint(dst, uint64(inner.ID()))
}

func serializeTypes(dst []byte, types []zng.Type) []byte {
	for _, typ := range types {
		switch typ := typ.(type) {
		default:
			panic(fmt.Sprintf("bzng cannot serialize type: %s", typ))
		case *zng.TypeRecord:
			dst = serializeTypeRecord(dst, typ.Columns)
		case *zng.TypeSet:
			dst = serializeTypeSet(dst, typ.InnerType)
		case *zng.TypeVector:
			dst = serializeTypeVector(dst, typ.Type)
		}
	}
	return dst
}