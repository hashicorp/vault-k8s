package agent_inject

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-k8s/agent-inject/agent"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/mattbaird/jsonpatch"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
)

var (
	deserializer = func() runtime.Decoder {
		codecs := serializer.NewCodecFactory(runtime.NewScheme())
		return codecs.UniversalDeserializer()
	}

	kubeSystemNamespaces = []string{
		metav1.NamespaceSystem,
		metav1.NamespacePublic,
	}
)

// Handler is the HTTP handler for admission webhooks.
type Handler struct {
	// RequireAnnotation means that the annotation must be given to inject.
	// If this is false, injection is default.
	RequireAnnotation  bool
	VaultAddress       string
	VaultAuthPath      string
	ImageVault         string
	Clientset          kubernetes.Interface
	Log                hclog.Logger
	RevokeOnShutdown   bool
	UserID             string
	GroupID            string
	SameID             bool
	SetSecurityContext bool
}

// Handle is the http.HandlerFunc implementation that actually handles the
// webhook request for admission control. This should be registered or
// served via an HTTP server.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	h.Log.Info("Request received", "Method", r.Method, "URL", r.URL)

	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		msg := fmt.Sprintf("Invalid content-type: %q", ct)
		http.Error(w, msg, http.StatusBadRequest)
		h.Log.Warn("warning for request", "Warn", msg, "Code", http.StatusBadRequest)
		return
	}

	var body []byte
	if r.Body != nil {
		var err error
		if body, err = ioutil.ReadAll(r.Body); err != nil {
			msg := fmt.Sprintf("error reading request body: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			h.Log.Error("error on request", "Error", msg, "Code", http.StatusBadRequest)
			return
		}
	}
	if len(body) == 0 {
		msg := "Empty request body"
		http.Error(w, msg, http.StatusBadRequest)
		h.Log.Error("warning for request", "Warn", msg, "Code", http.StatusBadRequest)
		return
	}

	var admReq v1beta1.AdmissionReview
	var admResp v1beta1.AdmissionReview
	if _, _, err := deserializer().Decode(body, nil, &admReq); err != nil {
		msg := fmt.Sprintf("error decoding admission request: %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		h.Log.Error("error on request", "Error", msg, "Code", http.StatusInternalServerError)
		return
	} else {
		admResp.Response = h.Mutate(admReq.Request)
	}

	resp, err := json.Marshal(&admResp)
	if err != nil {
		msg := fmt.Sprintf("error marshalling admission response: %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		h.Log.Error("error on request", "Error", msg, "Code", http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(resp); err != nil {
		h.Log.Error("error writing response", "Error", err)
	}
}

// Mutate takes an admission request and performs mutation if necessary,
// returning the final API response.
func (h *Handler) Mutate(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

	// On CREATE/UPDATE events, req.Object.Raw has the pod spec. For
	// DELETE events, req.OldObject.Raw has the pod spec.
	reqRaw := req.Object.Raw
	if reqRaw == nil {
		reqRaw = req.OldObject.Raw
	}

	// Decode the pod from the request
	var pod corev1.Pod
	if err := json.Unmarshal(reqRaw, &pod); err != nil {
		h.Log.Error("could not unmarshal request to pod: %s", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	// Build the basic response
	resp := &v1beta1.AdmissionResponse{
		Allowed: true,
		UID:     req.UID,
	}

	h.Log.Debug("checking if should inject agent..")
	if req.Operation != "DELETE" {
		inject, err := agent.ShouldInject(&pod)
		if err != nil {
			err := fmt.Errorf("error checking if should inject agent: %s", err)
			return admissionError(err)
		} else if !inject {
			return resp
		}
	} else {
		delete, err := agent.ShouldDelete(&pod)
		if err != nil {
			err := fmt.Errorf("error checking if should delete configmap for agent: %s", err)
			return admissionError(err)
		} else if !delete {
			return resp
		}

		configMapName := pod.Annotations[agent.AnnotationAgentGeneratedConfigMapName]
		h.Log.Debug(fmt.Sprintf("deleting configmap %s..", configMapName))

		err = h.Clientset.CoreV1().ConfigMaps(req.Namespace).Delete(configMapName, &metav1.DeleteOptions{})
		if err != nil {
			err := fmt.Errorf("error deleting generated configmap for agent: %s", err)
			return admissionError(err)
		}
		return resp
	}

	h.Log.Debug("checking namespaces..")
	if strutil.StrListContains(kubeSystemNamespaces, req.Namespace) {
		err := fmt.Errorf("error with request namespace: cannot inject into system namespaces: %s", req.Namespace)
		return admissionError(err)
	}

	h.Log.Debug("setting default annotations..")
	var patches []*jsonpatch.JsonPatchOperation
	cfg := agent.AgentConfig{
		Image:              h.ImageVault,
		Address:            h.VaultAddress,
		AuthPath:           h.VaultAuthPath,
		Namespace:          req.Namespace,
		RevokeOnShutdown:   h.RevokeOnShutdown,
		UserID:             h.UserID,
		GroupID:            h.GroupID,
		SameID:             h.SameID,
		SetSecurityContext: h.SetSecurityContext,
	}

	err := agent.Init(&pod, cfg)
	if err != nil {
		err := fmt.Errorf("error adding default annotations: %s", err)
		return admissionError(err)
	}

	h.Log.Debug("creating new agent..")
	agentSidecar, err := agent.New(&pod, patches)
	if err != nil {
		err := fmt.Errorf("error creating new agent sidecar: %s", err)
		return admissionError(err)
	}

	h.Log.Debug("validating agent configuration..")
	err = agentSidecar.Validate()
	if err != nil {
		err := fmt.Errorf("error validating agent configuration: %s", err)
		return admissionError(err)
	}

	h.Log.Debug("creating patches for the pod..")
	patch, err := agentSidecar.Patch()
	if err != nil {
		err := fmt.Errorf("error creating patch for agent: %s", err)
		return admissionError(err)
	}

	if agentSidecar.ConfigMapName == "" {
		data := make(map[string]string)
		if agentSidecar.PrePopulate {
			data["config-init.hcl"] = agentSidecar.InitConfig
		}

		if !agentSidecar.PrePopulateOnly {
			data["config.hcl"] = agentSidecar.SidecarConfig
		}

		config := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      agentSidecar.GeneratedConfigMapName,
				Namespace: req.Namespace,
				Annotations: map[string]string{
					"vault-agent-injector": "true",
				},
			},
			Data: data,
		}

		if req.Operation == "UPDATE" {
			_, err := h.Clientset.CoreV1().ConfigMaps(req.Namespace).Update(config)
			if err != nil {
				h.Log.Debug(fmt.Sprintf("error updating configMap: %s", err))
				err := fmt.Errorf("error updating agent configuration configmap: %s", err)
				return admissionError(err)
			}
		} else {
			_, err := h.Clientset.CoreV1().ConfigMaps(req.Namespace).Create(config)
			if err != nil {
				h.Log.Debug(fmt.Sprintf("error creating configMap: %s", err))
				err := fmt.Errorf("error creating agent configuration configmap: %s", err)
				return admissionError(err)
			}
		}
	}

	resp.Patch = patch
	patchType := v1beta1.PatchTypeJSONPatch
	resp.PatchType = &patchType

	return resp
}

func admissionError(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
