// Package zval implements serialization and deserialzation for zson values.
//
// Values of primitive type are represented by an unsigned integer tag and an
// optional byte sequence.  A tag of zero indicates that the value is unset, and
// no byte sequence follows.  A nonzero tag indicates that the value is set, and
// the value itself follows as a byte sequence of length tag-1.
//
// Values of container type (record, set, or vector) are represented similarly,
// with the byte sequence containing a sequence of zero or more serialized
// values.
package zval

import (
	"encoding/binary"
	"fmt"
)

// Iter iterates over a sequence of zvals.
type Iter []byte

// Done returns true if no zvals remain.
func (i *Iter) Done() bool {
	return len(*i) == 0
}

// Next returns the next zval.  It returns an empty slice for an empty or
// zero-length zval and nil for an unset zval.
func (i *Iter) Next() ([]byte, error) {
	// Uvarint is zero for an unset zval; otherwise, it is the value's
	// length plus one.
	u64, n := Uvarint(*i)
	if n <= 0 {
		return nil, fmt.Errorf("bad uvarint: %d", n)
	}
	if u64 == 0 {
		*i = (*i)[n:]
		return nil, nil
	}
	u64--
	val := (*i)[n : n+int(u64)]
	*i = (*i)[n+int(u64):]
	return val, nil
}

// AppendContainer appends to dst a zval container comprising the zvals in vals.
func AppendContainer(dst []byte, vals [][]byte) []byte {
	var n int
	for _, v := range vals {
		n += sizeBytes(v)
	}
	dst = AppendUvarint(dst, 1+uint64(n))
	for _, v := range vals {
		dst = AppendValue(dst, v)
	}
	return dst
}

// AppendValue appends to dst the zval in val.
func AppendValue(dst []byte, val []byte) []byte {
	if val == nil {
		return AppendUvarint(dst, 0)
	}
	dst = AppendUvarint(dst, 1+uint64(len(val)))
	return append(dst, val...)
}

// sizeBytes returns the number of bytes required by AppendValue to represent
// the zval in val.
func sizeBytes(val []byte) int {
	// This really is correct even when data is nil.
	return sizeUvarint(1+uint64(len(val))) + len(val)
}

// AppendUvarint is like encoding/binary.PutUvarint but appends to dst instead
// of writing into it.
func AppendUvarint(dst []byte, u64 uint64) []byte {
	for u64 >= 0x80 {
		dst = append(dst, byte(u64)|0x80)
		u64 >>= 7
	}
	return append(dst, byte(u64))
}

// Uvarint just calls binary.Uvarint.  It's here for symmetry with
// AppendUvarint.
func Uvarint(buf []byte) (uint64, int) {
	return binary.Uvarint(buf)
}

// sizeUvarint returns the number of bytes required by AppendUvarint to
// represent u64.
func sizeUvarint(u64 uint64) int {
	return len(AppendUvarint(make([]byte, 0, binary.MaxVarintLen64), u64))
}