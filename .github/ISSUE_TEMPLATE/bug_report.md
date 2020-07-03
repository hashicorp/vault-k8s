---
name: Bug report
about: Let us know about a bug!
title: ''
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Deploy application annotated for vault-agent injection
2. ...
4. See error (vault injector logs, vault-agent logs, etc.)

Application deployment:

```yaml
# Paste your application deployment yaml here.
# Be sure to scrub any sensitive values!
```

Other useful info to include here: `kubectl describe deployment <app>` and `kubectl describe replicaset <app>` output.

**Expected behavior**
A clear and concise description of what you expected to happen.

**Environment**
* Kubernetes version: 
  * Distribution or cloud vendor (OpenShift, EKS, GKE, AKS, etc.):
  * Other configuration options or runtime services (istio, etc.):
* vault-k8s version:

**Additional context**
Add any other context about the problem here.
