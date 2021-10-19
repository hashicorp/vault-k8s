module github.com/hashicorp/vault-k8s

go 1.16

require (
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/cenkalti/backoff/v4 v4.1.1
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-secure-stdlib/tlsutil v0.1.1
	github.com/hashicorp/vault/sdk v0.1.14-0.20191205220236-47cffd09f972
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/kr/text v0.2.0
	github.com/mattbaird/jsonpatch v0.0.0-20171005235357-81af80346b1a
	github.com/mitchellh/cli v1.0.0
	github.com/operator-framework/operator-lib v0.6.0
	github.com/pkg/errors v0.9.1
	github.com/posener/complete v1.2.1 // indirect
	github.com/prometheus/client_golang v1.11.0
	github.com/radovskyb/watcher v1.0.7
	github.com/stretchr/testify v1.7.0
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
)
