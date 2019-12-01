package resolver

import (
	"testing"

	"github.com/mccanne/zq/pkg/zeek"
	"github.com/mccanne/zq/pkg/zson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTableAddColumns(t *testing.T) {
	tab := NewTable()
	d := tab.GetByColumns([]zeek.Column{{"s1", zeek.TypeString}})
	r, err := zson.NewTestRecord(d, "S1")
	require.NoError(t, err)
	cols := []zeek.Column{{"ts", zeek.TypeTime}, {"s2", zeek.TypeString}}
	r, err = tab.AddColumns(r, cols, []string{"123.456", "S2"})
	require.NoError(t, err)
	assert.EqualValues(t, 123456000000, r.Ts)
	assert.EqualValues(t, "S1", r.Slice(0).Contents())
	assert.EqualValues(t, "123.456", r.Slice(1).Contents())
	assert.EqualValues(t, "S2", r.Slice(2).Contents())
	assert.Nil(t, r.Slice(4))
}
