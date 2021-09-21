#!/bin/bash

#create ipam controller authentication RBAC
kubectl create -f f5-ipam-ctlr-clusterrole.yaml
kubectl create -f f5-ipam-schema.yaml
kubectl create -f f5-ipam-deployment.yaml