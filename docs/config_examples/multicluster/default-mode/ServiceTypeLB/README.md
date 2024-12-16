# ServiceType LB discovery for external clusters.

Processing of serviceType LB resource from external clusters including HA peer cluster is supported through default mode.
 
## Configuration

To enbale discovery of service Type LB resources from primary cluster, set serviceTypeLBDiscovery to true for cluster through extendedSpec in configmap

`config`

```
extendedSpec: |
    mode: default
    highAvailabilityCIS:
      primaryEndPoint: http://10.145.72.114:8001
      probeInterval: 30
      retryInterval: 3
      primaryCluster:
        clusterName: cluster1
        secret: default/kubeconfig1
        serviceTypeLBDiscovery: true # If set to true then CIS will watch for serviceTypeLB in this cluster.default is false
      secondaryCluster:
        clusterName: cluster2
        secret: default/kubeconfig2
        serviceTypeLBDiscovery: true # If set to true then CIS will watch for serviceTypeLB in this cluster.default is false
    externalClustersConfig:
    - clusterName: cluster3
      secret: default/kubeconfig3
      serviceTypeLBDiscovery: true
    - clusterName: cluster4
      secret: default/kubeconfig4
      serviceTypeLBDiscovery: false
 ```

### Note:

* Policy referred through annotation in service need to be created in same cluster and same namespace as service.
* If multiple services are annotated with same IP, older service processed is honored and later is treated as invalid config.


   
