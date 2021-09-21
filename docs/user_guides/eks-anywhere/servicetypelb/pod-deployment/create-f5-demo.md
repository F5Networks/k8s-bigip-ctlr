#!/bin/bash

#create container f5-demo
kubectl create -f f5-demo-deployment.yaml
kubectl create -f f5-demo-service.yaml