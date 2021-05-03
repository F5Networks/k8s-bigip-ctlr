#!/bin/bash

#delete kubernetes nginx-ingress container, authentication and RBAC
kubectl delete -f ns-and-sa.yaml
kubectl delete -f rbac.yaml
kubectl delete -f default-server-secret.yaml
kubectl delete -f nginx-config.yaml
kubectl delete -f ingress-class.yaml
kubectl delete -f nginx-ingress.yaml
kubectl delete -f nginx-service.yaml