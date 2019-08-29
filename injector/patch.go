package injector

import (
	"strings"

	"github.com/mattbaird/jsonpatch"
	corev1 "k8s.io/api/core/v1"
)

func addVolume(target, add []corev1.Volume, base string) []jsonpatch.JsonPatchOperation {
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

func addContainer(target, add []corev1.Container, base string) []jsonpatch.JsonPatchOperation {
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

func addEnvVar(target, add []corev1.EnvVar, base string) []jsonpatch.JsonPatchOperation {
	var result []jsonpatch.JsonPatchOperation
	first := len(target) == 0
	var value interface{}
	for _, v := range add {
		value = v
		path := base
		if first {
			first = false
			value = []corev1.EnvVar{v}
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

func updateAnnotation(target, add map[string]string) []jsonpatch.JsonPatchOperation {
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
			Path:      "/metadata/annotations/" + escapeJSONPointer(key),
			Value:     value,
		})
	}

	return result
}

// https://tools.ietf.org/html/rfc6901
func escapeJSONPointer(s string) string {
	s = strings.Replace(s, "~", "~0", -1)
	s = strings.Replace(s, "/", "~1", -1)
	return s
}
