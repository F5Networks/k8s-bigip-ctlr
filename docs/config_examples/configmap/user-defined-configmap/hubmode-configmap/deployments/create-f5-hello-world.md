Below shell script creates `f5-hello-world` related deployments in namespace foo and bar

```
#!/bin/bash

kubectl create -f f5-hello-world-deployment.yaml
kubectl create -f f5-hello-world-service.yaml
```
