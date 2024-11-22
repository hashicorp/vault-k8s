// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent_inject

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/evanphx/json-patch"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-k8s/agent-inject/agent"
	"github.com/hashicorp/vault-k8s/agent-inject/internal"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func basicHandler() Handler {
	return Handler{
		VaultAddress:    "https://vault:8200",
		VaultAuthPath:   "kubernetes",
		ImageVault:      "vault",
		Log:             hclog.Default().Named("handler"),
		DefaultTemplate: agent.DefaultTemplateType,
	}
}

func TestHandlerHandle(t *testing.T) {
	basicSpec := corev1.PodSpec{
		InitContainers: []corev1.Container{
			{
				Name: "web-init",
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "foobar",
						MountPath: "serviceaccount/somewhere",
					},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name: "web",
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "foobar",
						MountPath: "serviceaccount/somewhere",
					},
				},
			},
		},
	}

	basicSpecWithMounts := *basicSpec.DeepCopy()
	basicSpecWithMounts.InitContainers[0].VolumeMounts = append(basicSpecWithMounts.InitContainers[0].VolumeMounts, corev1.VolumeMount{
		Name:      "tobecopied",
		MountPath: "/etc/somewhereelse",
	})

	cases := []struct {
		Name    string
		Handler Handler
		Req     admissionv1.AdmissionRequest
		Err     string // expected error string, not exact
		Patches jsonpatch.Patch
	}{
		{
			"kube-system namespace",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: metav1.NamespaceSystem,
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject: "true",
							agent.AnnotationVaultRole:   "demo",
						},
					},
					Spec: basicSpec,
				}),
			},
			"error with request namespace",
			nil,
		},

		{
			"already injected",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentStatus: "injected",
						},
					},

					Spec: basicSpec,
				}),
			},
			"",
			nil,
		},

		{
			"no injection by default",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Object: encodeRaw(t, &corev1.Pod{
					Spec: basicSpec,
				}),
			},
			"",
			nil,
		},

		{
			"injection disabled",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject: "false",
							agent.AnnotationVaultRole:   "demo",
						},
					},
					Spec: basicSpec,
				}),
			},
			"",
			nil,
		},

		{
			"basic pod injection",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject: "true",
							agent.AnnotationVaultRole:   "demo",
						},
					},
					Spec: basicSpec,
				}),
			},
			"",
			[]jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers/-", nil),
				internal.AddOp("/spec/initContainers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(agent.AnnotationAgentStatus), nil),
			},
		},

		{
			"init first ",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject:    "true",
							agent.AnnotationVaultRole:      "demo",
							agent.AnnotationAgentInitFirst: "true",
						},
					},
					Spec: basicSpec,
				}),
			},
			"",
			[]jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.RemoveOp("/spec/initContainers"),
				internal.AddOp("/spec/initContainers", nil),
				internal.AddOp("/spec/initContainers/-", nil),
				internal.AddOp("/spec/initContainers/1/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(agent.AnnotationAgentStatus), nil),
			},
		},

		{
			"configmap pod injection",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject:    "true",
							agent.AnnotationAgentConfigMap: "demo",
						},
					},
					Spec: basicSpec,
				}),
			},
			"",
			[]jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers/-", nil),
				internal.AddOp("/spec/initContainers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(agent.AnnotationAgentStatus), nil),
			},
		},
		{
			"tls pod injection",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject:    "true",
							agent.AnnotationAgentConfigMap: "demo",
							agent.AnnotationVaultTLSSecret: "demo",
						},
					},
					Spec: basicSpec,
				}),
			},
			"",
			[]jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers/-", nil),
				internal.AddOp("/spec/initContainers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(agent.AnnotationAgentStatus), nil),
			},
		},

		{
			"tls no configmap pod injection",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject:    "true",
							agent.AnnotationVaultRole:      "demo",
							agent.AnnotationVaultTLSSecret: "demo",
						},
					},
					Spec: basicSpec,
				}),
			},
			"",
			[]jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers/-", nil),
				internal.AddOp("/spec/initContainers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(agent.AnnotationAgentStatus), nil),
			},
		},

		{
			"tls no configmap no init pod injection",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject:      "true",
							agent.AnnotationVaultRole:        "demo",
							agent.AnnotationVaultTLSSecret:   "demo",
							agent.AnnotationAgentPrePopulate: "false",
						},
					},
					Spec: basicSpec,
				}),
			},
			"",
			[]jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(agent.AnnotationAgentStatus), nil),
			},
		},

		{
			"tls no configmap init only pod injection",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject:          "true",
							agent.AnnotationVaultRole:            "demo",
							agent.AnnotationVaultTLSSecret:       "demo",
							agent.AnnotationAgentPrePopulateOnly: "true",
						},
					},
					Spec: basicSpec,
				}),
			},
			"",
			[]jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers/-", nil),
				internal.AddOp("/spec/initContainers/0/volumeMounts/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(agent.AnnotationAgentStatus), nil),
			},
		},
		{
			"copy volume mounts pod injection",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject:           "true",
							agent.AnnotationVaultRole:             "demo",
							agent.AnnotationAgentCopyVolumeMounts: "web-init",
						},
					},
					Spec: basicSpecWithMounts,
				}),
			},
			"",
			[]jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers/-", nil),
				internal.AddOp("/spec/initContainers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(agent.AnnotationAgentStatus), nil),
			},
		},
		{
			"invalid default template",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "foo",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject:                "true",
							agent.AnnotationVaultRole:                  "demo",
							agent.AnnotationAgentInjectDefaultTemplate: "foobar",
						},
					},
					Spec: basicSpec,
				}),
			},
			"invalid default template type",
			nil,
		},
		{
			"shareProcessNamespaceAdded",
			basicHandler(),
			admissionv1.AdmissionRequest{
				Namespace: "test",
				Object: encodeRaw(t, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							agent.AnnotationAgentInject:                "true",
							agent.AnnotationVaultRole:                  "demo",
							agent.AnnotationAgentShareProcessNamespace: "true",
						},
					},
					Spec: basicSpecWithMounts,
				}),
			},
			"",
			[]jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers/-", nil),
				internal.AddOp("/spec/initContainers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/shareProcessNamespace", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(agent.AnnotationAgentStatus), nil),
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.Name, func(t *testing.T) {
			req := require.New(t)
			resp := (tt.Handler.Mutate(&tt.Req)).Resp
			if (tt.Err == "") != resp.Allowed {
				t.Fatalf("allowed: %v, expected err: %v", resp.Allowed, tt.Err)
			}
			if tt.Err != "" {
				req.Contains(resp.Result.Message, tt.Err)
				return
			}

			var actual jsonpatch.Patch
			if len(resp.Patch) > 0 {
				req.NoError(json.Unmarshal(resp.Patch, &actual))
				for i := range actual {
					delete(actual[i], "value")
				}
			}
			for i := range tt.Patches {
				delete(tt.Patches[i], "value")
			}
			req.Equal(tt.Patches, actual)
		})
	}
}

// Test that an incorrect content type results in an error.
func TestHandlerHandle_badContentType(t *testing.T) {
	req, err := http.NewRequest("POST", "/", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	h := Handler{Log: hclog.Default().Named("handler")}
	rec := httptest.NewRecorder()
	h.Handle(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "content-type")
}

// Test that no body results in an error
func TestHandlerHandle_noBody(t *testing.T) {
	req, err := http.NewRequest("POST", "/", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	h := Handler{Log: hclog.Default().Named("handler")}
	rec := httptest.NewRecorder()
	h.Handle(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "body")
}

// encodeRaw is a helper to encode some data into a RawExtension.
func encodeRaw(t *testing.T, input interface{}) runtime.RawExtension {
	data, err := json.Marshal(input)
	require.NoError(t, err)
	return runtime.RawExtension{Raw: data}
}
