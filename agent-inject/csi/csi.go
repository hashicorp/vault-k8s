package csi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-k8s/agent-inject/internal/patch"
	"github.com/mattbaird/jsonpatch"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// annotationCSISecretProviderClasses configures which SPCs to mount. Multiple SPCs can
// be specified as a comma-separated list.
const annotationCSISecretProviderClasses = "vault.hashicorp.com/csi-secret-provider-classes"

func ShouldInject(pod *corev1.Pod) bool {
	for a := range pod.Annotations {
		if a == annotationCSISecretProviderClasses {
			return true
		}
	}

	return false
}

func GeneratePatches(k8sClient *kubernetes.Clientset, pod *corev1.Pod) ([]*jsonpatch.JsonPatchOperation, error) {
	var patches []*jsonpatch.JsonPatchOperation
	secretProviderClasses := strings.Split(pod.Annotations[annotationCSISecretProviderClasses], ",")

	volumes := make([]corev1.Volume, 0, len(secretProviderClasses))
	volumeMounts := make([]corev1.VolumeMount, 0, len(secretProviderClasses))
	var env []corev1.EnvVar
	trueValue := true
	for _, spc := range secretProviderClasses {
		volumes = append(volumes, corev1.Volume{
			Name: fmt.Sprintf("%s-volume", spc),
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver:   "secrets-store.csi.k8s.io",
					ReadOnly: &trueValue,
					VolumeAttributes: map[string]string{
						"secretProviderClass": spc,
					},
				},
			},
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      fmt.Sprintf("%s-volume", spc),
			MountPath: fmt.Sprintf("/var/run/secrets/vault/csi/%s", spc),
			ReadOnly:  true,
		})

		// Fetch SPC config
		spcResp := k8sClient.RESTClient().
			Get().
			AbsPath("/apis/secrets-store.csi.x-k8s.io/v1").
			Namespace(pod.Namespace).
			Resource("SecretProviderClasses").
			Name(spc).
			Do(context.Background())

		var status int
		if err := spcResp.StatusCode(&status).Error(); err != nil {
			return nil, fmt.Errorf("failed to fetch SecretProviderClass %q: (%d) %w", spc, status, err)
		}

		body, _ := spcResp.Raw()
		var spcConfig SecretProviderClass
		if err := json.Unmarshal(body, &spcConfig); err != nil {
			return nil, err
		}

		for _, secret := range spcConfig.Spec.SecretObjects {
			for _, entry := range secret.Data {
				env = append(env, corev1.EnvVar{
					Name: entry.Key,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: secret.SecretName,
							},
							Key: entry.Key,
						},
					},
				})
			}
		}
	}

	// Add volumes
	patches = append(patches, patch.AddObjects(pod.Spec.Volumes, volumes, "/spec/volumes")...)

	for i, container := range pod.Spec.Containers {
		// Add volume mounts
		patches = append(patches, patch.AddObjects(
			container.VolumeMounts,
			volumeMounts,
			fmt.Sprintf("/spec/containers/%d/volumeMounts", i))...)

		// Sync to environment variables.
		patches = append(patches, patch.AddObjects(
			container.Env,
			env,
			fmt.Sprintf("/spec/containers/%d/env", i))...)
	}

	return patches, nil
}

// SecretProviderClass only specifies the SPC fields that are of interest to the injector.
type SecretProviderClass struct {
	Spec struct {
		SecretObjects []struct {
			SecretName string `json:"secretName"`
			Data       []struct {
				Key string `json:"key"`
			}
		} `json:"secretObjects"`
	} `json:"spec"`
}
