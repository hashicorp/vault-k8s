package agent

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"time"
)

const (
	DefaultMapTemplate  = "{{ with secret \"%s\" }}{{ range $k, $v := .Data }}{{ $k }}: {{ $v }}\n{{ end }}{{ end }}"
	DefaultJSONTemplate = "{{ with secret \"%s\" }}{{ .Data | toJSON }}\n{{ end }}"
	DefaultTemplateType = "map"
	PidFile             = "/home/vault/.pid"
	TokenFile           = "/home/vault/.vault-token"
)

// Config is the top level struct that composes a Vault Agent
// configuration file.
type Config struct {
	AutoAuth       *AutoAuth       `json:"auto_auth"`
	ExitAfterAuth  bool            `json:"exit_after_auth"`
	PidFile        string          `json:"pid_file"`
	Vault          *VaultConfig    `json:"vault"`
	Templates      []*Template     `json:"template,omitempty"`
	Listener       []*Listener     `json:"listener,omitempty"`
	Cache          *Cache          `json:"cache,omitempty"`
	TemplateConfig *TemplateConfig `json:"template_config,omitempty"`
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
	Contents       string `json:"contents,omitempty"`
	LeftDelim      string `json:"left_delimiter,omitempty"`
	RightDelim     string `json:"right_delimiter,omitempty"`
	Command        string `json:"command,omitempty"`
	Source         string `json:"source,omitempty"`
	Perms          string `json:"perms,omitempty"`
}

// Listener defines the configuration for Vault Agent Cache Listener
type Listener struct {
	Type       string `json:"type"`
	Address    string `json:"address"`
	TLSDisable bool   `json:"tls_disable"`
}

// Cache defines the configuration for the Vault Agent Cache
type Cache struct {
	UseAutoAuthToken string        `json:"use_auto_auth_token"`
	Persist          *CachePersist `json:"persist,omitempty"`
}

// CachePersist defines the configuration for persistent caching in Vault Agent
type CachePersist struct {
	Type                    string `json:"type"`
	Path                    string `json:"path"`
	KeepAfterImport         bool   `json:"keep_after_import,omitempty"`
	ExitOnErr               bool   `json:"exit_on_err,omitempty"`
	ServiceAccountTokenFile string `json:"service_account_token_file,omitempty"`
}

// TemplateConfig defines the configuration for template_config in Vault Agent
type TemplateConfig struct {
	ExitOnRetryFailure         bool   `json:"exit_on_retry_failure"`
	StaticSecretRenderInterval string `json:"static_secret_render_interval,omitempty"`
}

func (a *Agent) newTemplateConfigs() []*Template {
	var templates []*Template
	for _, secret := range a.Secrets {
		template := secret.Template
		templateFile := secret.TemplateFile
		if templateFile == "" {
			template = secret.Template
			if template == "" {
				switch a.DefaultTemplate {
				case "json":
					template = fmt.Sprintf(DefaultJSONTemplate, secret.Path)
				case "map":
					template = fmt.Sprintf(DefaultMapTemplate, secret.Path)
				}
			}
		}

		filePathAndName := fmt.Sprintf("%s/%s", secret.MountPath, secret.Name)
		if secret.FilePathAndName != "" {
			filePathAndName = filepath.Join(secret.MountPath, secret.FilePathAndName)
		}

		tmpl := &Template{
			Source:      templateFile,
			Contents:    template,
			Destination: filePathAndName,
			LeftDelim:   "{{",
			RightDelim:  "}}",
			Command:     secret.Command,
		}
		if secret.FilePermission != "" {
			tmpl.Perms = secret.FilePermission
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
				Type:      a.Vault.AuthType,
				Namespace: a.Vault.Namespace,
				MountPath: a.Vault.AuthPath,
				Config:    a.Vault.AuthConfig,
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
		Templates: a.newTemplateConfigs(),
		TemplateConfig: &TemplateConfig{
			ExitOnRetryFailure:         a.VaultAgentTemplateConfig.ExitOnRetryFailure,
			StaticSecretRenderInterval: a.VaultAgentTemplateConfig.StaticSecretRenderInterval,
		},
	}

	if a.InjectToken {
		config.AutoAuth.Sinks = append(config.AutoAuth.Sinks, &Sink{
			Type: "file",
			Config: map[string]interface{}{
				"path": path.Join(a.Annotations[AnnotationVaultSecretVolumePath], "token"),
			},
		})
	}

	cacheListener := []*Listener{
		{
			Type:       "tcp",
			Address:    fmt.Sprintf("127.0.0.1:%s", a.VaultAgentCache.ListenerPort),
			TLSDisable: true,
		},
	}
	if a.VaultAgentCache.Persist {
		config.Listener = cacheListener
		config.Cache = &Cache{
			UseAutoAuthToken: a.VaultAgentCache.UseAutoAuthToken,
			Persist: &CachePersist{
				Type:      "kubernetes",
				Path:      cacheVolumePath,
				ExitOnErr: a.VaultAgentCache.ExitOnErr,
			},
		}
	} else if a.VaultAgentCache.Enable && !a.PrePopulateOnly && !init {
		config.Listener = cacheListener
		config.Cache = &Cache{
			UseAutoAuthToken: a.VaultAgentCache.UseAutoAuthToken,
		}
	}

	return config.render()
}

func (c *Config) render() ([]byte, error) {
	return json.Marshal(c)
}
