#!/bin/bash

#delete container f5-demo
kubectl delete -f f5-demo-service.yaml
kubectl delete -f f5-demo-deployment.yaml