package patch

import (
	"strings"

	"github.com/mattbaird/jsonpatch"
	corev1 "k8s.io/api/core/v1"
)

func AddVolume(target, add []corev1.Volume, base string) []jsonpatch.JsonPatchOperation {
	var result []jsonpatch.JsonPatchOperation
	first := len(target) == 0
	var value interface{}
	for _, v := range add {
		value = v
		path := base
		if first {
			first = false
			value = []corev1.Volume{v}
		} else {
			path = path + "/-"
		}

		result = append(result, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      path,
			Value:     value,
		})
	}
	return result
}

func AddVolumeMount(target, add []corev1.VolumeMount, base string) []jsonpatch.JsonPatchOperation {
	var result []jsonpatch.JsonPatchOperation
	first := len(target) == 0
	var value interface{}
	for _, v := range add {
		value = v
		path := base
		if first {
			first = false
			value = []corev1.VolumeMount{v}
		} else {
			path = path + "/-"
		}

		result = append(result, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      path,
			Value:     value,
		})
	}
	return result
}

func AddContainer(target, add []corev1.Container, base string) []jsonpatch.JsonPatchOperation {
	var result []jsonpatch.JsonPatchOperation
	first := len(target) == 0
	var value interface{}
	for _, container := range add {
		value = container
		path := base
		if first {
			first = false
			value = []corev1.Container{container}
		} else {
			path = path + "/-"
		}

		result = append(result, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      path,
			Value:     value,
		})
	}

	return result
}

func UpdateAnnotation(target, add map[string]string) []jsonpatch.JsonPatchOperation {
	var result []jsonpatch.JsonPatchOperation
	if len(target) == 0 {
		result = append(result, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      "/metadata/annotations",
			Value:     add,
		})

		return result
	}

	for key, value := range add {
		result = append(result, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      "/metadata/annotations/" + EscapeJSONPointer(key),
			Value:     value,
		})
	}

	return result
}

// https://tools.ietf.org/html/rfc6901
func EscapeJSONPointer(s string) string {
	s = strings.Replace(s, "~", "~0", -1)
	s = strings.Replace(s, "/", "~1", -1)
	return s
}
