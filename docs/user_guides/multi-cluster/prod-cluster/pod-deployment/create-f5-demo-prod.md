#!/bin/bash

#create container f5-demo-prod
kubectl create -f f5-demo-prod-deployment.yaml
kubectl create -f f5-demo-prod-service.yaml