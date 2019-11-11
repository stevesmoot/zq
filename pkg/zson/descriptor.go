package zson

//XXX need to add lock pointer to each Descriptor?

import (
	"encoding/json"

	"github.com/mccanne/zq/pkg/zeek"
)

// Resolver is an interface for looking up Descriptor objects from the descriptor id.
type Resolver interface {
	Lookup(td int) *Descriptor
}

// Descriptor describes the field names and types of a Tuple.
// It is a list of the column descriptors along with a
// map to do a fast lookup table of column index by field name
type Descriptor struct {
	ID   int
	Type *zeek.TypeRecord
	LUT  map[string]int
}

// UnmarshalJSON satisfies the interface for json.Unmarshaler.
func (d *Descriptor) UnmarshalJSON(in []byte) error {
	if err := json.Unmarshal(in, &d.Type); err != nil {
		return err
	}
	d.createLUT()
	return nil
}

// MarshalJSON satisfies the interface for json.Marshaler.
func (d *Descriptor) MarshalJSON() ([]byte, error) {
	return json.MarshalIndent(d.Type, "", "\t")
}

func (d *Descriptor) ColumnOfField(field string) (int, bool) {
	v, ok := d.LUT[field]
	return v, ok
}

func (d *Descriptor) HasField(field string) bool {
	_, ok := d.LUT[field]
	return ok
}

func (d *Descriptor) Key() string {
	return d.Type.Key
}

func NewDescriptor(typ *zeek.TypeRecord) *Descriptor {
	d := &Descriptor{ID: -1, Type: typ}
	d.createLUT()
	return d
}

func (d *Descriptor) createLUT() {
	d.LUT = make(map[string]int)
	for k, col := range d.Type.Columns {
		d.LUT[col.Name] = k
	}
}