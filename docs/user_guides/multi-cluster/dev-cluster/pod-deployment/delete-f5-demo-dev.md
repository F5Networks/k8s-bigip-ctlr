#!/bin/bash

#delete container f5-demo
kubectl delete -f f5-demo-dev-deployment.yaml
kubectl delete -f f5-demo-dev-service.yaml