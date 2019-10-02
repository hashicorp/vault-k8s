# Acceptance tests for vault-k8s
# Requirements

* `openssl`
* `kubectl`: https://kubernetes.io/docs/tasks/tools/install-kubectl/
* Minikube: https://minikube.sigs.k8s.io/docs/start/
* Virtualbox: https://www.virtualbox.org
* Helm: https://helm.sh/docs/using_helm/

## Minikube 

```bash
$ minikube start

$ helm init --history-max 200
```

## Run Tests

```bash
bats .
```
