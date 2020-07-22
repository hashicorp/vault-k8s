package agent

import (
	"strings"

	"github.com/mattbaird/jsonpatch"
	corev1 "k8s.io/api/core/v1"
)

// TODO this can be broken down into a common code and type switched.

func addVolumes(target, volumes []corev1.Volume, base string) []*jsonpatch.JsonPatchOperation {
	var result []*jsonpatch.JsonPatchOperation
	first := len(target) == 0
	var value interface{}
	for _, v := range volumes {
		value = v
		path := base
		if first {
			first = false
			value = []corev1.Volume{v}
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

func addVolumeMounts(target, mounts []corev1.VolumeMount, base string) []*jsonpatch.JsonPatchOperation {
	var result []*jsonpatch.JsonPatchOperation
	first := len(target) == 0
	var value interface{}
	for _, v := range mounts {
		value = v
		path := base
		if first {
			first = false
			value = []corev1.VolumeMount{v}
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

func addContainers(target, containers []corev1.Container, base string) []*jsonpatch.JsonPatchOperation {
	var result []*jsonpatch.JsonPatchOperation
	first := len(target) == 0
	var value interface{}
	for _, container := range containers {
		value = container
		path := base
		if first {
			first = false
			value = []corev1.Container{container}
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
