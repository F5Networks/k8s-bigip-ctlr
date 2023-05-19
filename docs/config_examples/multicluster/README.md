# MultiClusterSupport

This page documents the behaviour of MultiClusterSupport. Check the Known Issues section for more information on features not supported.
## Contents

[Overview](#overview)

## Overview

MultiCluster support allows users to create services in more than one Kubernetes/Openshift clusters and use them as the backend services for Virtual servers on BIG-IP by referencing them in Routes(Currently it's only supported with Routes).

**Note**: 
* CIS supports processing of routes in traditional way as well as with NextGen Controller and with multi cluster support.
* Currently, only nodePort is supported.


Below is the sample representing MultiClusterConfigs in Extended Global ConfigMap.
```
  extendedSpec: |
    highAvailabilityClusterConfigs:   ---------------------------|----------------------------|
      mode:                                                      |                            |
        type: active                                             |                            |
      primaryClusterEndPoint: http://10.145.72.114:8001          |                            |
      probeInterval: 30                                          |                            |
      retryInterval: 3                                           |                            |
      primaryCluster:                                            |---> Cluster configs for    |
        clusterName: cluster1                                    |     High availability      |
        secret: default/kubeconfig1                              |     clusters               |---> Multicluster configs
      secondaryCluster:                                          |                            |
        clusterName: cluster2                                    |                            |
        secret: default/kubeconfig2                              |                            |
    multiClusterConfigs:    -------------------------------------|                            |
    - clusterName: cluster3                                      |                            |
      secret: default/kubeconfig3                                |---> Cluster configs for    |
    - clusterName: cluster4                                      |     all other clusters     |
      secret: default/kubeconfig4                                |     except HA clusters     |
    - clusterName: cluster5                                      |                            |
      secret: default/kubeconfig5  ------------------------------|----------------------------|
    extendedRouteSpec:
    - namespace: foo   -------------------------------------|
      vserverAddr: 10.8.0.4                                 |
      vserverName: nextgenroutes                            |----------------> RouteGroup with namespace
      allowOverride: true                                   |
      bigIpPartition: MultiTenant                           |
      policyCR: default/sample-policy  _____________________|
    - namespace: bar -------------------------------------|
      vserverAddr: 10.8.0.5                               |----------------> RouteGroup with namespace
      allowOverride: false           _____________________|
```

### highAvailabilityClusterConfigs Parameters

| Parameter              | Required | Description                                                 | Default | Examples                  |
|------------------------|----------|-------------------------------------------------------------|-------|---------------------------|
| mode                   | Optional | Type of high availability mode                              | -     | -                         |
| primaryClusterEndPoint | Mandatory | Endpoint to check health of primary cluster                 | -     | http://10.145.72.114:8001 |
| probeInterval          | Optional | Time interval between health check (in seconds)             | 60      | 30                        |
| retryInterval          | Optional | Time interval between recheck when primary cluster is down (in seconds) | 15      | 3                         |
| primaryCluster         | Mandatory | Primary cluster config                                      | -     | -                         |
| secondaryCluster       | Mandatory | Secondary cluster config                                    | -     | -                         |


### mode Parameters
| Parameter | Required | Description                                     | Default | Examples      |
|-----------|----------|-------------------------------------------------|---------|---------------|
| type      | Optional | Type of high availability mode (active/standby) | standby | active |

Specifies whether the HA cluster is configured with active mode or standby mode
* If mode Type: active, CIS fetches service from both the HA clusters whenever it's referenced in Route Spec.
* If mode Type: standby (default), CIS fetches service from only the local cluster whenever it's referenced in a Route Spec.


### primaryCluster/secondaryCluster Parameters

| Parameter | Required  | Description                                                               | Default | Examples                  |
| --------- |-----------|---------------------------------------------------------------------------|--------|---------------------------|
| clusterName | Mandatory | Name of the cluster                                                       | -      | cluster1                  |
| secret | Mandatory | Name of the secret created for kubeconfig (format: namespace/secret-name) | -      | test/secret-kubeconfig1   |


### multiClusterConfigs Parameters

| Parameter | Required  | Description                                                               | Default | Examples                  |
| --------- |-----------|---------------------------------------------------------------------------|--------|---------------------------|
| clusterName | Mandatory | Name of the cluster                                                       | -      | cluster1                  |
| secret | Mandatory | Name of the secret created for kubeconfig (format: namespace/secret-name) | -      | test/secret-kubeconfig1   |


**Note**: In order to run CIS in high availability mode cis-type parameter (primary/secondary) needs to be set in the CIS deployment arguments.
* It's recommended to provide both primaryCluster and secondaryCluster configs in the extendedConfigMap.

### PrimaryCluster Health Probe
 
Health probe parameters are provided in highAvailabilityClusterConfigs in extended configmap, help ensure high availability of CIS as the CIS running in secondary cluster continuously monitors the health of primary cluster, if it's down then the secondary CIS takes the responsibility of posting declarations to BIG-IP.
**Note**: primaryClusterEndPoint is a mandatory parameter if CIS is intended to run in multiCluster HA mode.

### Assumptions for CIS HA clusters

* Both the clusters in the HA cluster pair should have the same resources that CIS needs to monitor (like routes, services etc).
* For CIS running in HA mode, for any service specified in a Route that CIS monitors, pool members for the Virtual server associated with the Route will be fetched from both HA clusters(if mode type is set to active) along with the other clusters if virtual-server.f5.com/multiClusterServices is specified.

### MultiClusterServices
Services running in any other K8S/Openshift clusters apart from the HA cluster pair can be referenced in the route annotations as mentioned below:
```
virtual-server.f5.com/multiClusterServices: 
'[
     {
         "clusterName": "cluster2", 
         "svcName": "svc-pytest-foo-1-com", 
         "namespace": "foo", 
         "port": 80 
     }
]'
```

### MultiClusterServices Parameters

| Parameter | Required  | Description                                             | Default | Examples |
| --------- |-----------|---------------------------------------------------------|--------|----------|
| clusterName | Mandatory | Name of the cluster                                     | -      | cluster1 |
| svcName | Mandatory | Name of the service                                     | -      | svc-1    |
| namespace | Mandatory  | Namespace where the service is created                  | -      | test     |
| port | Optional  | port of the service  (for named port use string value ) | -      | 80       |


## Known issues
* Multi cluster feature doesn't work with CIS running in cluster mode(as of now).

## FAQ

### Is extended configMap mandatory for multiCluster support?
Yes. Multi cluster support only works with extended configmap.

