#!/usr/bin/env bats

load _helpers

@test "test/acceptance: testing inject" {
	local init_status=$(kubectl exec "$(name_prefix)-0" -- vault status -format=json |
    jq -r '.initialized')
  [ "${init_status}" == "true" ]

  local sealed_status=$(kubectl exec "$(name_prefix)-0" -- vault status -format=json |
    jq -r '.sealed' )
  [ "${sealed_status}" == "false" ]

	# assuming annotations as specified in https://github.com/jasonodonnell/vault-agent-demo/blob/master/app/patch-file-annotations.yaml#L7
  local secret_available=$(kubectl exec "$(name_prefix)-0" -- cat /vault/secrets/foo)
  [ "${secret_available}" == "bar" ]
}
