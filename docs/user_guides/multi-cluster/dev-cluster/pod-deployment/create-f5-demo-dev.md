#!/bin/bash

#create container f5-demo-dev
kubectl create -f f5-demo-dev-deployment.yaml
kubectl create -f f5-demo-dev-service.yaml