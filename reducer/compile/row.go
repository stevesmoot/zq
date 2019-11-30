package compile

import (
	"github.com/mccanne/zq/pkg/zeek"
	"github.com/mccanne/zq/pkg/zson"
	"github.com/mccanne/zq/pkg/zson/resolver"
	"github.com/mccanne/zq/pkg/zval"
	"github.com/mccanne/zq/reducer"
)

type Row struct {
	Defs     []CompiledReducer
	Reducers []reducer.Interface
	n        int
}

func (r *Row) Full() bool {
	return r.n == len(r.Defs)
}

func (r *Row) Touch(rec *zson.Record) {
	if r.Full() {
		return
	}
	if r.Reducers == nil {
		r.Reducers = make([]reducer.Interface, len(r.Defs))
	}
	for k, _ := range r.Defs {
		if r.Reducers[k] != nil {
			continue
		}
		red := r.Defs[k].Instantiate()
		r.Reducers[k] = red
		r.n++
	}
}

func (r *Row) Consume(rec *zson.Record) {
	r.Touch(rec)
	for _, red := range r.Reducers {
		if red != nil {
			red.Consume(rec)
		}
	}
}

// XXX steve update comment and check that we handle different types ...?
//  this isn't the same issue as group-by

// Result creates a new record from the results of the reducers.
// XXX this should use the forthcoming zson.Record fields "Values" and
// not bother with making raw
func (r *Row) Result(table *resolver.Table) *zson.Record {
	n := len(r.Reducers)
	columns := make([]zeek.Column, n)
	//XXX fix this logic here.  we just need to add Value columns and the
	//output layer will lookup descriptor, rebuild raw, insert _td (later PR)
	var zv zval.Encoding
	for k, red := range r.Reducers {
		val := reducer.Result(red)
		columns[k] = zeek.Column{Name: r.Defs[k].Target(), Type: val.Type()}
		zv = zval.Append(zv, val.TextZval(), zeek.IsContainer(val))
	}
	d := table.GetByColumns(columns)
	//XXX fix ts=0.  there should be NewRecord and NewRecordWithTs
	return zson.NewRecord(d, 0, zv)
}
