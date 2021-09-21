#!/bin/bash

#create kubernetes bigip container connecter, authentication and RBAC
kubectl create -f ns-and-sa.yaml
kubectl create -f rbac.yaml
kubectl create -f default-server-secret.yaml
kubectl create -f nginx-config.yaml
kubectl create -f ingress-class.yaml
kubectl create -f nginx-ingress.yaml
kubectl create -f nginx-service.yaml