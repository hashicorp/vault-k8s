package agent_inject

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

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
	VaultAuthType      string
	VaultAuthPath      string
	ImageVault         string
	Clientset          *kubernetes.Clientset
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
	// Decode the pod from the request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		h.Log.Error("could not unmarshal request to pod: %s", err)
		h.Log.Debug("%s", req.Object.Raw)
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
	inject, err := agent.ShouldInject(&pod)
	if err != nil && !strings.Contains(err.Error(), "no inject annotation found") {
		err := fmt.Errorf("error checking if should inject agent: %s", err)
		return admissionError(err)
	} else if !inject {
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
		AuthType:           h.VaultAuthType,
		AuthPath:           h.VaultAuthPath,
		Namespace:          req.Namespace,
		RevokeOnShutdown:   h.RevokeOnShutdown,
		UserID:             h.UserID,
		GroupID:            h.GroupID,
		SameID:             h.SameID,
		SetSecurityContext: h.SetSecurityContext,
	}
	err = agent.Init(&pod, cfg)
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
