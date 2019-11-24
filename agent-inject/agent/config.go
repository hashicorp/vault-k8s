package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	DefaultTemplate = "[[ with secret \"%s\" ]][[ range $k, $v := .Data ]][[ $k ]]: [[ $v ]]\n[[ end ]][[ end ]]"
	PidFile         = "/home/vault/.pid"
	TokenFile       = "/home/vault/.token"
)

// Config is the top level struct that composes a Vault Agent
// configuration file.
type Config struct {
	AutoAuth      *AutoAuth    `json:"auto_auth"`
	ExitAfterAuth bool         `json:"exit_after_auth"`
	PidFile       string       `json:"pid_file"`
	Vault         *VaultConfig `json:"vault"`
	Templates     []*Template  `json:"template"`
}

// Vault contains configuration for connecting to Vault servers
type VaultConfig struct {
	Address       string `json:"address"`
	CACert        string `json:"ca_cert,omitempty"`
	CAPath        string `json:"ca_path,omitempty"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
	ClientCert    string `json:"client_cert,omitempty"`
	ClientKey     string `json:"client_key,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
}

// AutoAuth is the configured authentication method and sinks
type AutoAuth struct {
	Method *Method `json:"method,omitempty"`
	Sinks  []*Sink `json:"sink,omitempty"`
}

// Method represents the configuration for the authentication backend
type Method struct {
	Type       string                 `json:"type"`
	MountPath  string                 `json:"mount_path,omitempty"`
	WrapTTLRaw interface{}            `json:"wrap_ttl,omitempty"`
	WrapTTL    time.Duration          `json:"-"`
	Namespace  string                 `json:"namespace,omitempty"`
	Config     map[string]interface{} `json:"config,omitempty"`
}

// Sink defines a location to write the authenticated token
type Sink struct {
	Type       string                 `json:"type"`
	WrapTTLRaw interface{}            `json:"wrap_ttl,omitempty"`
	WrapTTL    time.Duration          `json:"-"`
	DHType     string                 `json:"dh_type,omitempty"`
	DHPath     string                 `json:"dh_path,omitempty"`
	AAD        string                 `json:"aad,omitempty"`
	AADEnvVar  string                 `json:"aad_env_var,omitempty"`
	Config     map[string]interface{} `json:"config,omitempty"`
}

// Template defines the Consul Template parameters
type Template struct {
	CreateDestDirs bool   `json:"create_dest_dirs,omitempty"`
	Destination    string `json:"destination"`
	Contents       string `json:"contents"`
	LeftDelim      string `json:"left_delimiter,omitempty"`
	RightDelim     string `json:"right_delimiter,omitempty"`
}

func (a *Agent) newTemplatesConfigs() []*Template {
	var templates []*Template
	for _, secret := range a.Secrets {
		template := secret.Template
		if template == "" {
			template = fmt.Sprintf(DefaultTemplate, secret.Path)
		}

		tmpl := &Template{
			Contents:    template,
			Destination: fmt.Sprintf("/vault/secrets/%s", secret.Name),
			LeftDelim:   "[[",
			RightDelim:  "]]",
		}
		templates = append(templates, tmpl)
	}
	return templates
}

func (a *Agent) newConfig(init bool) ([]byte, error) {
	config := Config{
		PidFile:       PidFile,
		ExitAfterAuth: init,
		Vault: &VaultConfig{
			Address:       a.Vault.Address,
			CACert:        a.Vault.CACert,
			CAPath:        a.Vault.CAKey,
			ClientCert:    a.Vault.ClientCert,
			ClientKey:     a.Vault.ClientKey,
			TLSSkipVerify: a.Vault.TLSSkipVerify,
			TLSServerName: a.Vault.TLSServerName,
		},
		AutoAuth: &AutoAuth{
			Method: &Method{
				Type: "kubernetes",
				Config: map[string]interface{}{
					"role": a.Vault.Role,
				},
			},
			Sinks: []*Sink{
				{
					Type: "file",
					Config: map[string]interface{}{
						"path": TokenFile,
					},
				},
			},
		},
		Templates: a.newTemplatesConfigs(),
	}

	return config.render()
}

func (c *Config) render() ([]byte, error) {
	return json.Marshal(c)
}

func base64Encode(config []byte) string {
	return base64.StdEncoding.EncodeToString(config)
}
