#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CONFIG="configmap,secret,MutatingWebhookConfiguration"
DEPLOY="deployment,pod,replicaset,service,statefulset"
OBJECTS="${CONFIG?},${DEPLOY?}"

kubectl delete ${OBJECTS?} --selector=app=sidecar-injector --grace-period=0 --force
