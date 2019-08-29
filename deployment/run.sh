#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

${DIR?}/cleanup.sh

kubectl create secret generic sidecar-injector-webhook-certs \
   --from-file=key.pem=${DIR?}/certs/server-key.pem \
   --from-file=cert.pem=${DIR?}/certs/server-cert.pem

kubectl label secret sidecar-injector-webhook-certs app=sidecar-injector
kubectl create -f ${DIR?}/nginx-configmap.yaml
kubectl create -f ${DIR?}/deployment.yaml
