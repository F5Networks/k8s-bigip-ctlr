#!/bin/bash

#delete kubernetes bigip container connecter, authentication and RBAC
kubectl delete node bigip91
kubectl delete deployment k8s-bigip-ctlr-deployment-91 -n kube-system
kubectl delete clusterrolebinding k8s-bigip-ctlr-clusteradmin
kubectl delete serviceaccount k8s-bigip-ctlr -n kube-system
kubectl delete secret bigip-login -n kube-system