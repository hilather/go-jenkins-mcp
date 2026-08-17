package jenkins

import (
	"testing"
)

// Regression: the JSON trailing-garbage probe decoded into &struct{}{} — a
// trailing number/string/array fails to decode into a struct, and any decode
// error was treated as "no trailing data", so `{"a":1} 42` or `{"a":1} [1]`
// were reported JSONValid=true. The probe now decodes into any (catches every
// trailing value type) and treats trailing malformed fragments as invalid too.
func TestInspectJSON_TrailingGarbageDetected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		in        string
		wantValid bool
	}{
		{"clean object", `{"a":1}`, true},
		{"trailing object", `{"a":1} {"b":2}`, false},
		{"trailing number", `{"a":1} 42`, false},
		{"trailing string", `{"a":1} "x"`, false},
		{"trailing array", `{"a":1} [1]`, false},
		{"trailing garbage", `{"a":1} garbage`, false},
		{"trailing whitespace ok", "{\"a\":1}\n  \n", true},
	}
	for _, tc := range cases {
		valid, parseErr := inspectJSONValidity([]byte(tc.in))
		if valid != tc.wantValid {
			t.Errorf("%s: valid=%v want %v (parseErr=%q)", tc.name, valid, tc.wantValid, parseErr)
		}
		if !tc.wantValid && parseErr == "" {
			t.Errorf("%s: invalid input must carry a parse error note", tc.name)
		}
	}
}
