#!/bin/bash

#delete kubernetes cis container, authentication and RBAC 
kubectl delete node vxlan-tunnel-prod
kubectl delete deployment k8s-bigip-ctlr-deployment -n kube-system
kubectl delete clusterrolebinding k8s-bigip-ctlr-clusteradmin
kubectl delete serviceaccount k8s-bigip-ctlr -n kube-system
kubectl delete secret bigip-login -n kube-system