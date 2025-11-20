# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

schema = 1
artifacts {
  zip = [
    "vault-k8s_${version}_linux_386.zip",
    "vault-k8s_${version}_linux_amd64.zip",
    "vault-k8s_${version}_linux_arm.zip",
    "vault-k8s_${version}_linux_arm64.zip",
  ]
  container = [
    "vault-k8s_default_linux_386_${version}_${commit_sha}.docker.tar",
    "vault-k8s_default_linux_amd64_${version}_${commit_sha}.docker.tar",
    "vault-k8s_default_linux_arm64_${version}_${commit_sha}.docker.tar",
    "vault-k8s_default_linux_arm_${version}_${commit_sha}.docker.tar",
    "vault-k8s_ubi_linux_amd64_${version}_${commit_sha}.docker.redhat.tar",
    "vault-k8s_ubi_linux_arm64_${version}_${commit_sha}.docker.redhat.tar",
  ]
}
