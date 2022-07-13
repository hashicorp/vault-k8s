package patch

import (
	"github.com/mattbaird/jsonpatch"
)

func AddObjects[T any](target, objects []T, base string) []*jsonpatch.JsonPatchOperation {
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
