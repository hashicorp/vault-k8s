package agent

import (
	"strings"

	"github.com/mattbaird/jsonpatch"
)

func addObjects[T any](target, objects []T, base string) []*jsonpatch.JsonPatchOperation {
	var result []*jsonpatch.JsonPatchOperation
	first := len(target) == 0
	var value any
	for _, o := range objects {
		value = o
		path := base
		if first {
			first = false
			value = []T{o}
		} else {
			path = path + "/-"
		}

		result = append(result, &jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      path,
			Value:     value,
		})
	}
	return result
}

func removeContainers(path string) []*jsonpatch.JsonPatchOperation {
	var result []*jsonpatch.JsonPatchOperation

	return append(result, &jsonpatch.JsonPatchOperation{
		Operation: "remove",
		Path:      path,
	})
}

func updateAnnotations(target, annotations map[string]string) []*jsonpatch.JsonPatchOperation {
	var result []*jsonpatch.JsonPatchOperation
	if len(target) == 0 {
		result = append(result, &jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      "/metadata/annotations",
			Value:     annotations,
		})

		return result
	}

	for key, value := range annotations {
		result = append(result, &jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      "/metadata/annotations/" + EscapeJSONPointer(key),
			Value:     value,
		})
	}

	return result
}

// EscapeJSONPointer escapes a JSON string to be compliant with the
// JavaScript Object Notation (JSON) Pointer syntax RFC:
// https://tools.ietf.org/html/rfc6901.
func EscapeJSONPointer(s string) string {
	s = strings.Replace(s, "~", "~0", -1)
	s = strings.Replace(s, "/", "~1", -1)
	return s
}
