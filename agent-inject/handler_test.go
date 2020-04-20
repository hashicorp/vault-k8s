package agent_inject

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-k8s/agent-inject/agent"
	"github.com/mattbaird/jsonpatch"
	"github.com/stretchr/testify/require"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestHandlerHandle(t *testing.T) {
	var RunAsUser int64 = 1000720000
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
				SecurityContext: &corev1.SecurityContext{
					RunAsUser: &RunAsUser,
				},
			},
		},
	}

	cases := []struct {
		Name    string
		Handler Handler
		Req     v1beta1.AdmissionRequest
		Err     string // expected error string, not exact
		Patches []jsonpatch.JsonPatchOperation
	}{
		{
			"kube-system namespace",
			Handler{Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			Handler{Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			Handler{Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
				Object: encodeRaw(t, &corev1.Pod{
					Spec: basicSpec,
				}),
			},
			"",
			nil,
		},

		{
			"injection disabled",
			Handler{VaultAddress: "https://vault:8200", VaultAuthPath: "kubernetes", ImageVault: "vault", Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			Handler{VaultAddress: "https://vault:8200", VaultAuthPath: "kubernetes", ImageVault: "vault", Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			[]jsonpatch.JsonPatchOperation{
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/-",
				},
				{
					Operation: "add",
					Path:      "/metadata/annotations/" + agent.EscapeJSONPointer(agent.AnnotationAgentStatus),
				},
			},
		},

		{
			"init first ",
			Handler{VaultAddress: "https://vault:8200", VaultAuthPath: "kubernetes", ImageVault: "vault", Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			[]jsonpatch.JsonPatchOperation{
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/0/volumeMounts/-",
				},
				{
					Operation: "remove",
					Path:      "/spec/initContainers",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/1/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/-",
				},
				{
					Operation: "add",
					Path:      "/metadata/annotations/" + agent.EscapeJSONPointer(agent.AnnotationAgentStatus),
				},
			},
		},

		{
			"configmap pod injection",
			Handler{VaultAddress: "https://vault:8200", VaultAuthPath: "kubernetes", ImageVault: "vault", Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			[]jsonpatch.JsonPatchOperation{
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/-",
				},
				{
					Operation: "add",
					Path:      "/metadata/annotations/" + agent.EscapeJSONPointer(agent.AnnotationAgentStatus),
				},
			},
		},

		{
			"tls pod injection",
			Handler{VaultAddress: "https://vault:8200", VaultAuthPath: "kubernetes", ImageVault: "vault", Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			[]jsonpatch.JsonPatchOperation{
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/-",
				},
				{
					Operation: "add",
					Path:      "/metadata/annotations/" + agent.EscapeJSONPointer(agent.AnnotationAgentStatus),
				},
			},
		},

		{
			"tls no configmap pod injection",
			Handler{VaultAddress: "https://vault:8200", VaultAuthPath: "kubernetes", ImageVault: "vault", Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			[]jsonpatch.JsonPatchOperation{
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/-",
				},
				{
					Operation: "add",
					Path:      "/metadata/annotations/" + agent.EscapeJSONPointer(agent.AnnotationAgentStatus),
				},
			},
		},

		{
			"tls no configmap no init pod injection",
			Handler{VaultAddress: "https://vault:8200", VaultAuthPath: "kubernetes", ImageVault: "vault", Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			[]jsonpatch.JsonPatchOperation{
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/-",
				},
				{
					Operation: "add",
					Path:      "/metadata/annotations/" + agent.EscapeJSONPointer(agent.AnnotationAgentStatus),
				},
			},
		},

		{
			"tls no configmap init only pod injection",
			Handler{VaultAddress: "https://vault:8200", VaultAuthPath: "kubernetes", ImageVault: "vault", Log: hclog.Default().Named("handler")},
			v1beta1.AdmissionRequest{
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
			[]jsonpatch.JsonPatchOperation{
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/volumes",
				},
				{
					Operation: "add",
					Path:      "/spec/containers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/-",
				},
				{
					Operation: "add",
					Path:      "/spec/initContainers/0/volumeMounts/-",
				},
				{
					Operation: "add",
					Path:      "/metadata/annotations/" + agent.EscapeJSONPointer(agent.AnnotationAgentStatus),
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.Name, func(t *testing.T) {
			req := require.New(t)
			resp := tt.Handler.Mutate(&tt.Req)
			if (tt.Err == "") != resp.Allowed {
				t.Fatalf("allowed: %v, expected err: %v", resp.Allowed, tt.Err)
			}
			if tt.Err != "" {
				req.Contains(resp.Result.Message, tt.Err)
				return
			}

			var actual []jsonpatch.JsonPatchOperation
			if len(resp.Patch) > 0 {
				req.NoError(json.Unmarshal(resp.Patch, &actual))
				for i := range actual {
					actual[i].Value = nil
				}
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
