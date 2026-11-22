package scenario

import (
	"net/http"
	"strings"
	"testing"
)

func TestExtract(t *testing.T) {
	resp := &Response{
		Status: 201,
		Header: http.Header{"X-Photofinish-Variant": {"vuln"}, "Set-Cookie": {"a=1", "b=2"}, "x-lower": {"l"}},
		Body: []byte(`{"id":"c-1","total_cents":8100,"big":12345678901234567890,"ratio":0.5,"ok":true,
			"discounts":[{"code":"WELCOME10","amount":810}],"owner":{"name":"alice"},"none":null,"empty":[],
			"we-ird_key":"w"}`),
	}
	cases := []struct {
		spec, want, err string
	}{
		{spec: "status", want: "201"},
		{spec: "header:X-PhotoFinish-Variant", want: "vuln"},
		{spec: "header: x-photofinish-variant ", want: "vuln"},
		{spec: "header:X-Lower", want: "l"},
		{spec: "header:Set-Cookie", want: "a=1, b=2"},
		{spec: "header:Missing", err: "response has no Missing header"},
		{spec: "header:", err: "want header:Name"},
		{spec: "$.id", want: "c-1"},
		{spec: " $.id ", want: "c-1"},
		{spec: "$.total_cents", want: "8100"},
		{spec: "$.big", want: "12345678901234567890"},
		{spec: "$.ratio", want: "0.5"},
		{spec: "$.ok", want: "true"},
		{spec: "$.discounts[0].code", want: "WELCOME10"},
		{spec: "$.discounts[0]", want: `{"amount":810,"code":"WELCOME10"}`},
		{spec: "$.owner.name", want: "alice"},
		{spec: "$.empty", want: "[]"},
		{spec: "$.we-ird_key", want: "w"},
		{spec: "$.none", err: "$.none: the value is null"},
		{spec: "$.missing", err: `$.missing: $ has no key "missing"`},
		{spec: "$.owner.age", err: `$.owner has no key "age"`},
		{spec: "$.discounts[3]", err: "$.discounts has 1 elements, index 3 is out of range"},
		{spec: "$.id[0]", err: "$.id is a string, not a list"},
		{spec: "$.discounts.code", err: "$.discounts is a list, not an object"},
		{spec: "$.", err: "expected a name after '.'"},
		{spec: "$[x]", err: "must hold a non-negative index"},
		{spec: "$[-1]", err: "must hold a non-negative index"},
		{spec: "$[0", err: "missing ']'"},
		{spec: "$..id", err: "expected a name after '.'"},
		{spec: "$id", err: `unexpected 'i'`},
		{spec: "body", err: `unsupported extraction "body"`},
	}
	for _, c := range cases {
		got, err := Extract(c.spec, resp)
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("Extract(%q) error = %v, want %q", c.spec, err, c.err)
		case c.err == "" && err != nil:
			t.Errorf("Extract(%q): %v", c.spec, err)
		case c.err == "" && got != c.want:
			t.Errorf("Extract(%q) = %q, want %q", c.spec, got, c.want)
		}
	}
}

func TestExtractBodies(t *testing.T) {
	cases := []struct {
		name string
		resp *Response
		spec string
		want string
		err  string
	}{
		{name: "nil response", resp: nil, spec: "status", err: "no response"},
		{name: "status 0", resp: &Response{}, spec: "$", err: "no response"},
		{name: "not json", resp: &Response{Status: 500, Body: []byte("<html>")}, spec: "$.id", err: "the response body is not JSON (status 500)"},
		{name: "empty body", resp: &Response{Status: 204}, spec: "$", err: "not JSON"},
		{name: "trailing data", resp: &Response{Status: 200, Body: []byte(`{} {}`)}, spec: "$", err: "data after the JSON value"},
		{name: "whole scalar", resp: &Response{Status: 200, Body: []byte(` "x" `)}, spec: "$", want: "x"},
		{name: "top-level list", resp: &Response{Status: 200, Body: []byte(`[{"id":7}]`)}, spec: "$[0].id", want: "7"},
		{name: "status without headers", resp: &Response{Status: 404}, spec: "status", want: "404"},
	}
	for _, c := range cases {
		got, err := Extract(c.spec, c.resp)
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error = %v, want %q", c.name, err, c.err)
		case c.err == "" && (err != nil || got != c.want):
			t.Errorf("%s: %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}
