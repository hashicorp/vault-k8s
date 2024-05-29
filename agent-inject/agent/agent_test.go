// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testPod(annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "foo",
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "foobar",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "foobar",
							MountPath: "serviceaccount/somewhere",
						},
						{
							Name:      "tobecopied",
							MountPath: "/etc/somewhereelse",
							ReadOnly:  false,
						},
					},
				},
				{
					Name: "foo1",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "foo1",
							MountPath: "/data/foo1",
						},
					},
				},
				{
					Name: "foo2",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "foo2",
							MountPath: "/data/foo2",
						},
					},
				},
			},
		},
	}
}

func testPodIRSA(annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "foo",
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "foobar",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "foobar",
							MountPath: "serviceaccount/somewhere",
						},
					},
				},
				{
					Name: "aws-iam-token",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "aws-iam-token",
							MountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount",
						},
					},
				},
			},
		},
	}
}

func TestShouldInject(t *testing.T) {
	tests := []struct {
		annotations map[string]string
		phase       corev1.PodPhase
		inject      bool
	}{
		{map[string]string{AnnotationAgentInject: "true", AnnotationAgentStatus: ""}, corev1.PodPending, true},
		{map[string]string{AnnotationAgentInject: "false", AnnotationAgentStatus: ""}, corev1.PodPending, false},
		{map[string]string{AnnotationAgentInject: "true", AnnotationAgentStatus: "injected"}, corev1.PodPending, false},
		{map[string]string{AnnotationAgentInject: "false", AnnotationAgentStatus: "injected"}, corev1.PodPending, false},
		{map[string]string{AnnotationAgentInject: "true", AnnotationAgentStatus: "update"}, corev1.PodPending, true},
		{map[string]string{AnnotationAgentInject: "true", AnnotationAgentStatus: ""}, corev1.PodRunning, false},
		{map[string]string{AnnotationAgentInject: "true", AnnotationAgentStatus: ""}, corev1.PodSucceeded, false},
		{map[string]string{AnnotationAgentInject: "true", AnnotationAgentStatus: ""}, corev1.PodFailed, false},
		{map[string]string{AnnotationAgentInject: "true", AnnotationAgentStatus: "update"}, corev1.PodRunning, false},
	}

	for _, tt := range tests {
		pod := testPod(tt.annotations)
		pod.Status.Phase = tt.phase
		inject, err := ShouldInject(pod)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if inject != tt.inject {
			t.Errorf("expected should inject to be %v, got %v", tt.inject, inject)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		agent Agent
		valid bool
	}{
		{
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "foobar",
					TokenPath: "foobar",
				},
				ImageName:     "test",
				ConfigMapName: "test",
			}, true,
		},
		{
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "foobar",
					TokenPath: "foobar",
				},
				ImageName: "test",
				Vault: Vault{
					Role:     "test",
					Address:  "https://foobar.com:8200",
					AuthPath: "test",
					AuthType: "kubernetes",
				},
			}, true,
		},
		{
			Agent{
				Namespace: "",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "foobar",
					TokenPath: "foobar",
				},
				ImageName:     "test",
				ConfigMapName: "test",
			}, false,
		},
		{
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "",
					MountPath: "foobar",
					TokenPath: "foobar",
				},
				ImageName:     "test",
				ConfigMapName: "test",
			}, false,
		},
		{
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "",
					TokenPath: "foobar",
				},
				ImageName:     "test",
				ConfigMapName: "test",
			}, false,
		},
		{
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "foobar",
					TokenPath: "",
				},
				ImageName:     "test",
				ConfigMapName: "test",
			}, false,
		},
		{
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "foobar",
					TokenPath: "foobar",
				},
				ImageName:     "",
				ConfigMapName: "test",
			}, false,
		},
		{
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "foobar",
					TokenPath: "foobar",
				},
				ImageName: "test",
				Vault: Vault{
					Role:     "",
					Address:  "https://foobar.com:8200",
					AuthType: "kubernetes",
				},
			}, false,
		},
		{
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "foobar",
					TokenPath: "foobar",
				},
				ImageName: "test",
				Vault: Vault{
					Role:     "test",
					Address:  "",
					AuthType: "kubernetes",
				},
			}, false,
		},
		{
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "foobar",
					TokenPath: "foobar",
				},
				ImageName: "test",
				Vault: Vault{
					Role:     "test",
					Address:  "https://foobar.com:8200",
					AuthPath: "",
					AuthType: "kubernetes",
				},
			}, false,
		},
		{
			// Missing ServiceAccountTokenVolume.TokenPath
			Agent{
				Namespace: "test",
				ServiceAccountTokenVolume: &ServiceAccountTokenVolume{
					Name:      "foobar",
					MountPath: "foobar",
					TokenPath: "",
				},
				ImageName: "test",
				Vault: Vault{
					Role:     "test",
					Address:  "https://foobar.com:8200",
					AuthPath: "test",
					AuthType: "",
				},
			}, false,
		},
		{
			// Missing ServiceAccountTokenVolume
			Agent{
				Namespace: "test",
				ImageName: "test",
				Vault: Vault{
					Role:     "test",
					Address:  "https://foobar.com:8200",
					AuthPath: "test",
					AuthType: "",
				},
			}, false,
		},
	}

	for _, tt := range tests {
		err := tt.agent.Validate()

		if err != nil && tt.valid {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if err == nil && !tt.valid {
			t.Error("got no error, should have")
		}
	}
}

func Test_serviceaccount(t *testing.T) {
	tests := map[string]struct {
		pod           *corev1.Pod
		expected      *ServiceAccountTokenVolume
		expectedError string
	}{
		"no service accounts": {
			expected:      nil,
			expectedError: "failed to find service account volume mount",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{},
			},
		},
		"missing token volume": {
			expected:      nil,
			expectedError: `failed to find service account volume "projected-token"`,
			pod: &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						"vault.hashicorp.com/agent-service-account-token-volume-name": "projected-token",
					},
				},
			},
		},
		"token volume name mount missing from volumes": {
			expected:      nil,
			expectedError: `failed to find volume "missing" in Pod "test-pod" volumes`,
			pod: &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-pod",
					Annotations: map[string]string{
						"vault.hashicorp.com/agent-service-account-token-volume-name": "missing",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "missing",
									MountPath: "/not/a/projected/token/volume",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "projected-token",
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
												Path: "token",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		"missing tokenPath for volume that's mounted": {
			expected:      nil,
			expectedError: `failed to find tokenPath for projected volume "projected-token"`,
			pod: &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						"vault.hashicorp.com/agent-service-account-token-volume-name": "projected-token",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "projected-token",
									MountPath: "/var/run/secrets/special/serviceaccount",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "projected-token",
						},
					},
				},
			},
		},
		"missing tokenPath in volume": {
			expected:      nil,
			expectedError: `failed to find tokenPath for projected volume "projected-token"`,
			pod: &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						"vault.hashicorp.com/agent-service-account-token-volume-name": "projected-token",
					},
				},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						{
							Name: "projected-token",
						},
					},
				},
			},
		},
		"regular service account (not projected)": {
			expected: &ServiceAccountTokenVolume{
				Name:      "internal-app-token-n4pjn",
				MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
				TokenPath: "token",
			},
			expectedError: "",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "internal-app-token-n4pjn",
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "internal-app-token-n4pjn",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "internal-app-token-n4pjn",
								},
							},
						},
					},
				},
			},
		},
		"projected default service account": {
			expected: &ServiceAccountTokenVolume{
				Name:      "kube-api-access-4bfzq",
				MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
				TokenPath: "token",
			},
			expectedError: "",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "kube-api-access-4bfzq",
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "kube-api-access-4bfzq",
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
												Path: "token",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		"projected service account with annotation": {
			expected: &ServiceAccountTokenVolume{
				Name:      "projected-token",
				MountPath: "/var/run/secrets/special/serviceaccount",
				TokenPath: "vault-token",
			},
			expectedError: "",
			pod: &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						"vault.hashicorp.com/agent-service-account-token-volume-name": "projected-token",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "projected-token",
									MountPath: "/var/run/secrets/special/serviceaccount",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "projected-token",
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
												Path: "vault-token",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		"projected service account with annotation but not mounted": {
			expected: &ServiceAccountTokenVolume{
				Name:      "projected-token",
				MountPath: "/var/run/secrets/vault.hashicorp.com/serviceaccount",
				TokenPath: "vault-token",
			},
			expectedError: "",
			pod: &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						"vault.hashicorp.com/agent-service-account-token-volume-name": "projected-token",
					},
				},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						{
							Name: "projected-token",
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
												Path: "vault-token",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		"projected service account with audience": {
			expected: &ServiceAccountTokenVolume{
				Name:      "token",
				MountPath: "/var/run/secrets/vault.hashicorp.com/serviceaccount",
				TokenPath: "token",
				Audience:  "audience",
			},
			expectedError: "",
			pod: &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						"vault.hashicorp.com/vault-service-account-token-audience": "audience",
					},
				},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						{
							Name: "token",
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
												Path:     "token",
												Audience: "audience",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := serviceaccount(tc.pod)
			if len(tc.expectedError) > 0 {
				assert.EqualError(t, err, tc.expectedError)
			}
			assert.Equal(t, tc.expected, result)
		})
	}
}
