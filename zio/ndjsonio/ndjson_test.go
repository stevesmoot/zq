package ndjsonio

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio/zngio"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNDJSONWriter(t *testing.T) {
	type testcase struct {
		name, input, output string
	}
	cases := []testcase{
		{
			name: "null containers",
			input: `#0:record[dns:array[string],uri:array[string],email:set[string],ip:array[ip]]
0:[[google.com;]-;-;-;]
`,
			output: `{"dns":["google.com"],"email":null,"ip":null,"uri":null}`,
		},
		{
			name: "nested nulls",
			input: `#0:record[san:record[dns:array[string],uri:array[string],email:set[string],ip:array[ip]]]
0:[[[google.com;]-;-;-;]]
`,
			output: `{"san":{"dns":["google.com"],"email":null,"ip":null,"uri":null}}`,
		},
		{
			name: "empty containers",
			input: `#0:record[dns:array[string],uri:array[string],email:set[string],ip:array[ip]]
0:[[google.com;][][]-;]
`,
			output: `{"dns":["google.com"],"uri":[], "email":[],"ip":null}`,
		},
		{
			name: "nested empties",
			input: `#0:record[san:record[dns:array[string],uri:array[string],email:set[string],ip:array[ip]]]
0:[[[google.com;][][]-;]]
`,
			output: `{"san":{"dns":["google.com"],"uri":[], "email":[],"ip":null}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			w := NewWriter(&out)
			r := zngio.NewReader(strings.NewReader(c.input), resolver.NewContext())
			require.NoError(t, zbuf.Copy(zbuf.NopFlusher(w), r))
			NDJSONEq(t, c.output, out.String())
		})
	}
}

func TestNDJSON(t *testing.T) {
	type testcase struct {
		name, input, output string
	}
	cases := []testcase{
		{
			name:   "single line",
			input:  `{ "string1": "value1", "int1": 1, "double1": 1.2, "bool1": false }`,
			output: "",
		},
		{
			name: "skips empty lines",
			input: `{ "string1": "value1", "int1": 1, "double1": 1.2, "bool1": false }

		{"string1": "value2", "int1": 2, "double1": 2.3, "bool1": true }
		`,
			output: "",
		},
		{
			name: "nested containers",
			input: `{ "obj1": { "obj2": { "double1": 1.1 } } }
		{ "arr1": [ "string1", "string2", "string3" ] }`,
			output: "",
		},
		{
			name:   "null value",
			input:  `{ "null1": null }`,
			output: "",
		},
		{
			name:   "empty array",
			input:  `{ "arr1": [] }`,
			output: "",
		},
		{
			name:   "legacy nested fields",
			input:  `{ "s": "foo", "nest.s": "bar", "nest.n": 5 }`,
			output: `{ "s": "foo", "nest": { "s": "bar", "n": 5 }}`,
		},
		{
			name:   "string with unicode escape",
			input:  `{ "s": "Hello\u002c world!" }`,
			output: `{ "s": "Hello, world!" }`,
		},
		// Test that unicode combining characters are properly
		// normalized.  Note that in the input string, zq interprets
		// the \u escapes, while in the output string they are part of
		// the go string literal and interpreted by the go compiler.
		{
			name:   "string with unicode combining characters",
			input:  `{ "s": "E\u0301l escribio\u0301 un caso de prueba"}`,
			output: "{ \"s\": \"\u00c9l escribi\u00f3 un caso de prueba\"}",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			output := c.output
			if len(output) == 0 {
				output = c.input
			}
			runtestcase(t, c.input, output)
		})
	}
}

func runtestcase(t *testing.T, input, output string) {
	var out bytes.Buffer
	w := NewWriter(&out)
	r, err := NewReader(strings.NewReader(input), resolver.NewContext())
	require.NoError(t, err)
	require.NoError(t, zbuf.Copy(zbuf.NopFlusher(w), r))
	NDJSONEq(t, output, out.String())
}

func getLines(in string) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(in))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		lines = append(lines, string(line))
	}
	return lines, scanner.Err()
}

func NDJSONEq(t *testing.T, expected string, actual string) {
	expectedLines, err := getLines(expected)
	require.NoError(t, err)
	actualLines, err := getLines(actual)
	require.NoError(t, err)
	require.Len(t, expectedLines, len(actualLines))
	for i := range actualLines {
		require.JSONEq(t, expectedLines[i], actualLines[i])
	}
}

func TestNewRawFromJSON(t *testing.T) {
	type testcase struct {
		name, zng, json, defaultPath string
	}
	cases := []testcase{
		{
			name: "LongDuration",
			zng: `#0:record[_path:string,ts:time,span:duration]
0:[test;1573860644.637486;0.123456134;]`,
			json: `{"_path": "test", "ts": "2019-11-15T23:30:44.637486Z", "span": 0.1234561341234234}`,
		},
		{
			name: "TsISO8601",
			zng: `#0:record[_path:string,b:bool,i:int64,s:set[bool],ts:time,v:array[int64]]
0:[test;-;-;-;1573860644.637486;-;]`,
			json: `{"_path": "test", "ts":"2019-11-15T23:30:44.637486Z"}`,
		},
		{
			name: "TsEpoch",
			zng: `#0:record[_path:string,ts:time]
0:[test;1573860644.637486;]`,
			json: `{"_path": "test", "ts":1573860644.637486}`,
		},
		{
			name: "TsMillis",
			zng: `#0:record[_path:string,ts:time]
0:[test;1573860644.637000;]`,
			json: `{"_path": "test", "ts":1573860644637}`,
		},
		{
			name: "defaultPath",
			zng: `#0:record[_path:string,ts:time]
0:[inferred;1573860644.637000;]`,
			json:        `{"ts":1573860644637}`,
			defaultPath: "inferred",
		},
		{
			name: "defaultPath (unused)",
			zng: `#0:record[_path:string,ts:time]
0:[test;1573860644.637000;]`,
			json:        `{"_path": "test", "ts":1573860644637}`,
			defaultPath: "inferred",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := zngio.NewReader(strings.NewReader(c.zng), resolver.NewContext())
			expected, err := r.Read()
			require.NoError(t, err)
			typ := expected.Type
			ti := &typeInfo{
				flatDesc:   typ,
				descriptor: typ,
				jsonVals:   make([]jsonVal, len(typ.Columns)),
				path:       []byte(c.defaultPath),
			}
			raw, _, err := ti.newRawFromJSON([]byte(c.json))
			require.NoError(t, err)
			rec := &zng.Record{Type: typ, Raw: raw}
			assert.Equal(t, expected.String(), rec.String())
		})
	}
}

func TestNDJSONTypeErrors(t *testing.T) {
	typeConfig := TypeConfig{
		Descriptors: map[string][]interface{}{
			"http_log": []interface{}{
				map[string]interface{}{
					"name": "_path",
					"type": "string",
				},
				map[string]interface{}{
					"name": "ts",
					"type": "time",
				},
				map[string]interface{}{
					"name": "uid",
					"type": "bstring",
				},
				map[string]interface{}{
					"name": "id",
					"type": []interface{}{map[string]interface{}{
						"name": "orig_h",
						"type": "ip",
					},
					},
				},
			},
		},
		Rules: []Rule{
			Rule{"_path", "http", "http_log"},
		},
	}

	var cases = []struct {
		name        string
		result      typeStats
		input       string
		success     bool
		defaultPath string
	}{
		{
			name:   "Valid",
			result: typeStats{},
			input: `{"ts":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65","_path":"http"}
			{"uid":"CXY9a54W2dLZwzPXf1","ts":"2017-03-24T19:59:24.306076Z","id.orig_h":"10.10.7.65","_path":"http"}`,
			success: true,
		},
		{
			name:   "Extra field",
			result: typeStats{IncompleteDescriptor: 2, FirstBadLine: 1},
			input: `{"ts":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65","_path":"http", "extra_field": 1}
{"ts":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65","_path":"http"}
{"ts":"2017-03-24T19:59:24.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65","_path":"http", "extra_field": 1}`,
			success: true,
		},
		{
			name:   "Bad line number",
			result: typeStats{BadFormat: 1, FirstBadLine: 2},
			input: `{"ts":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65","_path":"http"}
{"hiddents":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65","_path":"http"}`,
			success: false,
		},
		{
			name:    "Missing Ts",
			result:  typeStats{BadFormat: 1, FirstBadLine: 1},
			input:   `{"uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65", "_path": "http"}` + "\n",
			success: false,
		},
		{
			name:    "Negative Ts",
			result:  typeStats{BadFormat: 1, FirstBadLine: 1},
			input:   `{"ts":"-1579438676.648","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65", "_path": "http"}` + "\n",
			success: false,
		},
		{
			name:    "Valid (inferred)",
			result:  typeStats{DescriptorNotFound: 1, FirstBadLine: 1},
			input:   `{"ts":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65","_path":"inferred"}`,
			success: false,
		},
		{
			name:    "Missing _path",
			result:  typeStats{MissingPath: 1, FirstBadLine: 1},
			input:   `{"ts":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65"}` + "\n",
			success: false,
		},
		{
			name:        "_path provided as defaultPath",
			result:      typeStats{},
			input:       `{"ts":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65"}` + "\n",
			success:     true,
			defaultPath: "http",
		},
		{
			name:        "invalid _path provided as defaultPath",
			result:      typeStats{DescriptorNotFound: 1, FirstBadLine: 1},
			input:       `{"ts":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65"}` + "\n",
			success:     false,
			defaultPath: "nosuchpath",
		},
		{
			name:        "invalid defaultPath doesn't override input _path",
			result:      typeStats{},
			input:       `{"_path": "http", "ts":"2017-03-24T19:59:23.306076Z","uid":"CXY9a54W2dLZwzPXf1","id.orig_h":"10.10.7.65"}` + "\n",
			success:     true,
			defaultPath: "nosuchpath",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			w := NewWriter(&out)
			r, err := NewReader(strings.NewReader(c.input), resolver.NewContext())
			require.NoError(t, err)

			err = r.ConfigureTypes(typeConfig, c.defaultPath)
			require.NoError(t, err)

			err = zbuf.Copy(zbuf.NopFlusher(w), r)
			if c.success {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, c.result, *r.stats.typeStats)
		})
	}
}
