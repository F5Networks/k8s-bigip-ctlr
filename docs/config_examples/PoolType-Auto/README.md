
## Pool Member Type - auto
If CIS is configured with the "auto" mode, CIS will learn the respective service type of the CIS monitored resources and populate the bigip pool members based on the service types<br>
In other words, CIS considers the poolMemberType as "cluster" when the respective service type is "clusterIP" and considers the poolMemberType as "nodeport" when the respective service type are "NodePort" and "LoadBalancer"<br>
"auto" poolMemberType can be considered as the combination of "nodeport" and "cluster". It adjusts the modes automatically based on the service Type.
## Configuration
```

poolMemberType: auto

```

## Detailed Example 
```
# note : any change to the cniConfig block requires the CIS to be restarted
    apiVersion: "cis.f5.com/v1"
    kind: DeployConfig
    metadata:
      name: cis-config
      namespace: kube-system
      labels:
        f5cr: "true"
    spec:
      baseConfig:
        namespaceLabel: controller=cis
        nodeLabel: controller=cis
        controllerIdentifier: cluster-1
      networkConfig:
        orchestrationCNI: ovn-k8s
        metaData:
          poolMemberType: auto
          sharedRouteMode: true
          networkCIDR: "10.1.0.0/16"
          staticRoutingMode: true
      as3Config:
        debugAS3: true
        postDelayAS3: 10
        documentAPI: true
      bigIpConfig:
        - bigIpAddress: 10.10.10.1
          haBigIpAddress: 10.10.10.2
          bigIpLabel: Hyderabad
          defaultPartition: test
```

# Supported Services
CIS in auto mode will learn the service types and process the pool members. Below service types are supported
with the respective pool member types

| CIS version | Service Type | Pool Members                                  | Staic Routing Required                  |
|-------------|--------------|-----------------------------------------------|-----------------------------------------|
| 3.x         | ClusterIP    | Pod IPs   (Same as CIS "cluster" poolMemberType)   | Yes |
| 3.x         | Headless     | Pod IPs   (Same as CIS "cluster" poolMemberType)   | Yes |
| 3.x         | NodePort     | Node IP's (Same as CIS "nodeport" poolMemberType)  | N/A                                     |
| 3.x         | LoadBalancer | Node IP's (Same as CIS "nodeport" poolMemberType)  | N/A                                     |


**Note:**

* With auto pool mode enabled, static routing is required to enable traffic to cluster type services(pods)
* For Headless service - service type will be ClusterIP. So pod IP will be configured on the BIG IP