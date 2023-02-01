// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"github.com/evanphx/json-patch"
	"github.com/hashicorp/vault-k8s/agent-inject/internal"
	corev1 "k8s.io/api/core/v1"
)

// TODO this can be broken down into a common code and type switched.

func addVolumes(target, volumes []corev1.Volume, base string) jsonpatch.Patch {
	var result jsonpatch.Patch
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

		result = append(result, internal.AddOp(path, value))
	}
	return result
}

func addVolumeMounts(target, mounts []corev1.VolumeMount, base string) jsonpatch.Patch {
	var result jsonpatch.Patch
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

		result = append(result, internal.AddOp(path, value))
	}
	return result
}

func removeContainers(path string) jsonpatch.Patch {
	return []jsonpatch.Operation{internal.RemoveOp(path)}
}

func addContainers(target, containers []corev1.Container, base string) jsonpatch.Patch {
	var result jsonpatch.Patch
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

		result = append(result, internal.AddOp(path, value))
	}

	return result
}

func updateAnnotations(target, annotations map[string]string) jsonpatch.Patch {
	var result jsonpatch.Patch
	if len(target) == 0 {
		return []jsonpatch.Operation{internal.AddOp("/metadata/annotations", annotations)}
	}

	for key, value := range annotations {
		result = append(result, internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(key), value))
	}

	return result
}

func updateShareProcessNamespace(shareProcessNamespace bool) jsonpatch.Patch {
	return []jsonpatch.Operation{
		internal.AddOp("/spec/shareProcessNamespace", shareProcessNamespace),
	}
}
