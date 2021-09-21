#!/bin/bash

#delete container f5-demo
kubectl delete -f f5-demo-prod-deployment.yaml
kubectl delete -f f5-demo-prod-service.yaml