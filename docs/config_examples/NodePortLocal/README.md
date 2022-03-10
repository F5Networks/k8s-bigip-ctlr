
## NodePortLocal (NPL) feature  in Antrea agent.
NodePortLocal (NPL) is a feature that runs as part of the Antrea Agent. Using this, each port of a Service backend Pod can be reached from the external network using a port of the Node on which the Pod is running.

## Prerequisites
Prior to versionv1.4, a feature gate, NodePortLocal, must be enabled on the antrea-agent for the feature to work.From v1.4, it was enabled by default
```
kind: ConfigMap
apiVersion: v1
metadata:
  name: antrea-config-dcfb6k2hkm
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      # True by default starting with Antrea v1.4
      # NodePortLocal: true
    nodePortLocal:
      enable: true
      # Uncomment if you need to change the port range.
      # portRange: 61000-62000    
```

## Configuration
* To enable npl feature set  --pool-member-type to nodeportlocal in CIS arguments. It is only applicable for antrea cni enabled clusters.
```
   args:
     --pool-member-type=nodeportlocal
```

* All Services used should be annoatated with nodeportlocal.antrea.io/enabled: "true" for slecting pods for NodePortLocal
```
apiVersion: v1
kind: Service
metadata:
  annotations:
    nodeportlocal.antrea.io/enabled: "true"
  labels:
    app: f5-hello-world
  name: f5-hello-world
spec:
  ports:
  - name: f5-hello-world
    port: 8080
    protocol: TCP
    targetPort: 8080
  selector:
    app: f5-hello-world
  type: ClusterIP
  
```
* All the pods will be annoated with nodeportlocal.antrea.io which has nodeport and ip information.

```
kubectl describe po f5-hello-world-6d859874b7-prf8l -n cis
Name:         f5-hello-world-6d859874b7-prf8l
Namespace:    cis
Priority:     0
Start Time:   Wed, 09 Mar 2022 00:17:30 -0800
Labels:       app=f5-hello-world
              pod-template-hash=6d859874b7
Annotations:  kubernetes.io/psp: cis-psp
              nodeportlocal.antrea.io: [{"podPort":8080,"nodeIP":"10.244.0.3","nodePort":40001}]

```
* CIS reads info from nodeportlocal.antrea.io to add endpoint info for virtualserver on BIGIP.
  
**Note:** 

  * NodePortLocal can only be used with Services of type ClusterIP or LoadBalancer.
  * The nodeportlocal.antrea.io annotation has no effect for Services of type NodePort or ExternalName.
  * It also has no effect for Services with an empty or missing Selector
  * CIS currently supports NPL feature with Ingress and virtualserver resource. Feature validated on k8s Tanzu infrastructue. 
