# name_prefix returns the prefix of the resources within Kubernetes.
name_prefix() {
    printf "vault"
}

# chart_dir returns the directory for the chart
chart_dir() {
    echo ${BATS_TEST_DIRNAME}/../..
}

deploy_nginx() {
# The nginx container will get the secrets by injection from the side car
# which is made available by the admissions webhook. 
#
# The admissions webhook also needs to modify the spec to include the correct
# service account.
cat <<EOF | kubectl create -f -
apiVersion: apps/v1 
kind: Deployment
metadata:
  name: nginx 
  labels:
    app: nginx
spec:
  selector:
    matchLabels:
      app: nginx 
  replicas: 1
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/vault-service: "http://vault:8200"
        vault.hashicorp.com/agent-inject-secret-foo: "kv/secret/foo:/vault/secrets/foo"
      labels:
        app: nginx 
    spec:
      containers:
      - name: nginx 
        image: nginx 
EOF
}

# wait for a pod to be ready
wait_for_running() {
    POD_NAME=$1

    check() {
        # This requests the pod and checks whether the status is running
        # and the ready state is true. If so, it outputs the name. Otherwise
        # it outputs empty. Therefore, to check for success, check for nonzero
        # string length.
        kubectl get pods $1 -o json | \
            jq -r 'select(
                .status.phase == "Running" and
                ([ .status.conditions[] | select(.type == "Ready" and .status == "False") ] | length) == 1
            ) | .metadata.namespace + "/" + .metadata.name'
    }

    for i in $(seq 60); do
        if [ -n "$(check ${POD_NAME})" ]; then
            echo "${POD_NAME} is running."
            sleep 10
            return
        fi

        echo "Waiting for ${POD_NAME} to be running..."
        sleep 2
    done

    echo "${POD_NAME} never entered running state."
    exit 1
}

wait_for_ready() {
    POD_NAME=$1

    check() {
        # This requests the pod and checks whether the status is running
        # and the ready state is true. If so, it outputs the name. Otherwise
        # it outputs empty. Therefore, to check for success, check for nonzero
        # string length.
        kubectl get pods $1 -o json | \
            jq -r 'select(
                .status.phase == "Ready" and
                ([ .status.conditions[] | select(.type == "Ready" and .status == "True") ] | length) == 1
            ) | .metadata.namespace + "/" + .metadata.name'
    }

    for i in $(seq 60); do
        if [ -n "$(check ${POD_NAME})" ]; then
            echo "${POD_NAME} is ready."
            sleep 10
            return
        fi

        echo "Waiting for ${POD_NAME} to be ready..."
        sleep 2
    done

    echo "${POD_NAME} never became ready."
    exit 1
}

setup() {
  helm install https://github.com/hashicorp/vault-helm/archive/master.tar.gz \
    --name vault

	wait_for_running $(name_prefix)-0
  
  # Vault Init
  export token=$(kubectl exec -ti "$(name_prefix)-0" -- \
    vault operator init -format=json -n 1 -t 1 | \
    jq -r '.unseal_keys_b64[0]')
  [ "${token}" != "" ]

  # Vault Unseal
  export pods=($(kubectl get pods -o json | jq -r '.items[].metadata.name'))
  for pod in "${pods[@]}"
  do
      kubectl exec -ti ${pod} -- vault operator unseal ${token}
  done

	deploy_nginx
}

teardown() {
  helm delete --purge $(name_prefix)
  kubectl delete deployment nginx
  kubectl delete --all pvc
}
