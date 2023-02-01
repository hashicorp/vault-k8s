// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package internal

import (
	"encoding/json"
	"strings"

	jsonpatch "github.com/evanphx/json-patch"
)

var (
	addOperation    = json.RawMessage(`"add"`)
	removeOperation = json.RawMessage(`"remove"`)
)

func AddOp(path string, value interface{}) jsonpatch.Operation {
	pathBytes, err := json.Marshal(path)
	if err != nil {
		panic(err) // shouldn't be possible
	}
	valueBytes, err := json.Marshal(value)
	if err != nil {
		panic(err) // shouldn't be possible
	}
	pathRaw := json.RawMessage(pathBytes)
	valueRaw := json.RawMessage(valueBytes)
	return map[string]*json.RawMessage{
		"op":    &addOperation,
		"path":  &pathRaw,
		"value": &valueRaw,
	}
}

func RemoveOp(path string) jsonpatch.Operation {
	pathBytes, err := json.Marshal(path)
	if err != nil {
		panic(err) // shouldn't be possible
	}
	pathRaw := json.RawMessage(pathBytes)
	return map[string]*json.RawMessage{
		"op":   &removeOperation,
		"path": &pathRaw,
	}
}

// EscapeJSONPointer escapes a JSON string to be compliant with the
// JavaScript Object Notation (JSON) Pointer syntax RFC:
// https://tools.ietf.org/html/rfc6901.
func EscapeJSONPointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}
