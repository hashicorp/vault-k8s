// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	DefaultLeftDelim    = "{{"
	DefaultRightDelim   = "}}"
	DefaultTemplateType = "map"
	PidFile             = "/home/vault/.pid"
	TokenFile           = "/home/vault/.vault-token"
)

// Config is the top level struct that composes a Vault Agent
// configuration file.
type Config struct {
	AutoAuth               *AutoAuth       `json:"auto_auth"`
	ExitAfterAuth          bool            `json:"exit_after_auth"`
	PidFile                string          `json:"pid_file"`
	Vault                  *VaultConfig    `json:"vault"`
	Templates              []*Template     `json:"template,omitempty"`
	Listener               []*Listener     `json:"listener,omitempty"`
	Cache                  *Cache          `json:"cache,omitempty"`
	TemplateConfig         *TemplateConfig `json:"template_config,omitempty"`
	DisableIdleConnections []string        `json:"disable_idle_connections,omitempty"`
	DisableKeepAlives      []string        `json:"disable_keep_alives,omitempty"`
	Telemetry              *Telemetry      `json:"telemetry,omitempty"`
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
	MinBackoff string                 `json:"min_backoff,omitempty"`
	MaxBackoff string                 `json:"max_backoff,omitempty"`
	Namespace  string                 `json:"namespace,omitempty"`
	Config     map[string]interface{} `json:"config,omitempty"`
	ExitOnErr  bool                   `json:"exit_on_err,omitempty"`
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
	ErrMissingKey  bool   `json:"error_on_missing_key,omitempty"`
}

// Listener defines the configuration for Vault Agent Cache Listener
type Listener struct {
	Type       string    `json:"type"`
	Address    string    `json:"address"`
	TLSDisable bool      `json:"tls_disable"`
	AgentAPI   *AgentAPI `json:"agent_api,omitempty"`
}

// AgentAPI defines the agent_api stanza for a listener
type AgentAPI struct {
	EnableQuit bool `json:"enable_quit"`
}

// Cache defines the configuration for the Vault Agent Cache
type Cache struct {
	UseAutoAuthToken string        `json:"use_auto_auth_token,omitempty"`
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
	ExitOnRetryFailure         bool     `json:"exit_on_retry_failure"`
	StaticSecretRenderInterval string   `json:"static_secret_render_interval,omitempty"`
	MaxConnectionsPerHost      int64    `json:"max_connections_per_host,omitempty"`
	LeaseRenewalThreshold      float64  `json:"lease_renewal_threshold,omitempty"`
}

// Telemetry defines the configuration for agent telemetry in Vault Agent.
type Telemetry struct {
	UsageGaugePeriod                   string   `json:"usage_gauge_period,omitempty"`
	MaximumGaugeCardinality            int      `json:"maximum_gauge_cardinality,omitempty"`
	DisableHostname                    bool     `json:"disable_hostname,omitempty"`
	EnableHostnameLabel                bool     `json:"enable_hostname_label,omitempty"`
	LeaseMetricsEpsilon                string   `json:"lease_metrics_epsilon,omitempty"`
	NumLeaseMetricsBuckets             int      `json:"num_lease_metrics_buckets,omitempty"`
	AddLeaseMetricsNamespaceLabels     bool     `json:"add_lease_metrics_namespace_labels,omitempty"`
	FilterDefault                      bool     `json:"filter_default,omitempty"`
	PrefixFilter                       []string `json:"prefix_filter,omitempty"`
	StatsiteAddress                    string   `json:"statsite_address,omitempty"`
	StatsdAddress                      string   `json:"statsd_address,omitempty"`
	CirconusApiToken                   string   `json:"circonus_api_token,omitempty"`
	CirconusApiApp                     string   `json:"circonus_api_app,omitempty"`
	CirconusApiURL                     string   `json:"circonus_api_url,omitempty"`
	CirconusSubmissionInterval         string   `json:"circonus_submission_interval,omitempty"`
	CirconusSubmissionURL              string   `json:"circonus_submission_url,omitempty"`
	CirconusCheckID                    string   `json:"circonus_check_id,omitempty"`
	CirconusCheckForceMetricActivation bool     `json:"circonus_check_force_metric_activation,omitempty"`
	CirconusCheckInstanceID            string   `json:"circonus_check_instance_id,omitempty"`
	CirconusCheckSearchTag             string   `json:"circonus_check_search_tag,omitempty"`
	CirconusCheckDisplayName           string   `json:"circonus_check_display_name,omitempty"`
	CirconusCheckTags                  string   `json:"circonus_check_tags,omitempty"`
	CirconusBrokerID                   string   `json:"circonus_broker_id,omitempty"`
	CirconusBrokerSelectTag            string   `json:"circonus_broker_select_tag,omitempty"`
	DogstatsdAddr                      string   `json:"dogstatsd_addr,omitempty"`
	DogstatsdTags                      []string `json:"dogstatsd_tags,omitempty"`
	PrometheusRetentionTime            string   `json:"prometheus_retention_time,omitempty"`
	StackdriverProjectID               string   `json:"stackdriver_project_id,omitempty"`
	StackdriverLocation                string   `json:"stackdriver_location,omitempty"`
	StackdriverNamespace               string   `json:"stackdriver_namespace,omitempty"`
	StackdriverDebugLogs               bool     `json:"stackdriver_debug_logs,omitempty"`
}

// newTelemetryConfig creates a Telemetry object from the accumulated agent telemetry annotations.
func (a *Agent) newTelemetryConfig() *Telemetry {
	var tel Telemetry
	if len(a.Vault.AgentTelemetryConfig) == 0 {
		return nil
	}
	// First get it out of the map[string]interface{} which was created when we parsed the annotations.
	telemetryBytes, err := json.Marshal(a.Vault.AgentTelemetryConfig)
	if err != nil {
		return nil
	}
	// Unmarshal it into a Telemetry object.
	if err = json.Unmarshal(telemetryBytes, &tel); err != nil {
		return nil
	}
	return &tel
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

		leftDelim := secret.LeftDelimiter
		if leftDelim == "" {
			leftDelim = DefaultLeftDelim
		}

		rightDelim := secret.RightDelimiter
		if rightDelim == "" {
			rightDelim = DefaultRightDelim
		}

		filePathAndName := fmt.Sprintf("%s/%s", secret.MountPath, secret.Name)
		if secret.FilePathAndName != "" {
			filePathAndName = filepath.Join(secret.MountPath, secret.FilePathAndName)
		}

		tmpl := &Template{
			Source:        templateFile,
			Contents:      template,
			Destination:   filePathAndName,
			LeftDelim:     leftDelim,
			RightDelim:    rightDelim,
			Command:       secret.Command,
			ErrMissingKey: secret.ErrMissingKey,
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
				Type:       a.Vault.AuthType,
				Namespace:  a.Vault.Namespace,
				MountPath:  a.Vault.AuthPath,
				Config:     a.Vault.AuthConfig,
				MinBackoff: a.Vault.AuthMinBackoff,
				MaxBackoff: a.Vault.AuthMaxBackoff,
				ExitOnErr:  a.AutoAuthExitOnError,
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
		Telemetry: a.newTelemetryConfig(),
		TemplateConfig: &TemplateConfig{
			ExitOnRetryFailure:         a.VaultAgentTemplateConfig.ExitOnRetryFailure,
			StaticSecretRenderInterval: a.VaultAgentTemplateConfig.StaticSecretRenderInterval,
			MaxConnectionsPerHost:      a.VaultAgentTemplateConfig.MaxConnectionsPerHost,
			LeaseRenewalThreshold:      a.VaultAgentTemplateConfig.LeaseRenewalThreshold,
		},
		DisableIdleConnections: a.DisableIdleConnections,
		DisableKeepAlives:      a.DisableKeepAlives,
	}

	if a.InjectToken {
		config.AutoAuth.Sinks = append(config.AutoAuth.Sinks, &Sink{
			Type: "file",
			Config: map[string]interface{}{
				"path": path.Join(a.Annotations[AnnotationVaultSecretVolumePath], "token"),
			},
		})
	}

	cacheListener := makeCacheListener(a.VaultAgentCache.ListenerPort)
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

	// If EnableQuit is true, set it on the listener. If a listener hasn't been
	// defined, set it on a new one. Also add a simple cache stanza since that's
	// required for an agent listener.
	if a.EnableQuit {
		if len(config.Listener) > 0 {
			config.Listener[0].AgentAPI = &AgentAPI{
				EnableQuit: a.EnableQuit,
			}
		} else {
			config.Listener = makeCacheListener(a.VaultAgentCache.ListenerPort)
			config.Listener[0].AgentAPI = &AgentAPI{
				EnableQuit: a.EnableQuit,
			}
		}
		if config.Cache == nil {
			// Cache is required for an agent listener
			config.Cache = &Cache{}
		}
	}

	return config.render()
}

func (c *Config) render() ([]byte, error) {
	return json.Marshal(c)
}

func makeCacheListener(port string) []*Listener {
	return []*Listener{
		{
			Type:       "tcp",
			Address:    fmt.Sprintf("127.0.0.1:%s", port),
			TLSDisable: true,
		},
	}
}
