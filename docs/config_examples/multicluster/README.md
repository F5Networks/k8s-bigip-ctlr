# MultiClusterSupport(Preview)

This page documents the behaviour of MultiClusterSupport. This is a preview release which supports limited features and is not recommended to use in production environments. Check the Known Issues section for more information on features not supported.

## Contents

[Overview](#overview)

[Topologies](#topologies)

[Configuration](#configuration)

[ExtendedSpecConfigMap](#extendedspecconfigmap)

[Examples](#examples)

[Known Issues](#known-issues)

[FAQ](#faq)


## Overview

MultiCluster support in CIS allows users to expose multiple apps spread across Openshift clusters using single BIGIP Virtual Server. Customer can deploy their apps in different openshift clusters and expose them using a route resource. 
Using MultiCluster implementation customer can deploy the CIS in HA topology or standalone CIS to expose the apps spread across openshift clusters.


**Note**: 
* CIS supports processing of routes in traditional way as well as with NextGen Controller and with multi cluster support.
* Currently, only nodePort is supported.

## Prerequisites
* Cluster node where CIS is deployed should be able to reach the API server of all openshift cluster. 
* extendedConfigMap needs to be created to run CIS in multiCluster mode.
* kube-config files for each cluster should be available for CIS to be able to access resources like Pods/Services/Endpoints/Nodes.

## Topologies

### Standalone CIS

In Standalone deployment of CIS, customer needs to deploy CIS only in one cluster, and he can create a route resource with multiCluster annotation to expose the apps in different openshift clusters.

![architecture](images/standaloneMultiCluster.png)

Below is the sample MultiCluster Config in Extended Global ConfigMap.
```
  extendedSpec: |
    multiClusterConfigs:    -------------------------------------|----------------------------|                            |
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

### High Availability CIS

#### Prerequisites
  * A pair of High Availability openshift clusters should be available, which has same applications running in both the clusters.
  * HealthCheck endpoint should be available to check the health of primary cluster. Currently, TCP/HTTP Health endpoints are supported.


In HA deployment of CIS, customer needs to deploy CIS in primary and secondary cluster. Customer also need to deploy the same extendedConfigMap in primary and secondary cluster. 
CIS will look for same service name in both primary and secondary cluster to expose the application via routes. Additionally, customer can also create the multiCluster annotation in the route definition to expose the applications in other clusters.

Customer can deploy CIS HA in two modes:
  * active mode - In this mode, CIS will add the pool members from both primary and secondary openshift cluster.
  * standby mode - In this mode, CIS will add the pool members only from active openshift cluster.

![architecture](images/haMultiCluster.png)

Below is the sample MultiCluster Configs with HA in Extended Global ConfigMap.
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

## Configuration 

### CIS Deployment Parameter

If you are using the High Availability setup with multi-cluster, you need to specify ```--cis-type``` parameter to define the primary and secondary cluster:


| Parameter | Required | Description                                                                         | Allowed Values       |
|-----------|----------|-------------------------------------------------------------------------------------|----------------------|
| cis-type  | Optional | Specify whether CIS run as primary or secondary in case of high availability setup. | primary or secondary |

Following is the sample deployment for primary CIS deployment.

```yaml
    spec:
      containers:
      - args:
        - --bigip-partition
        - <partition>
        - --bigip-url
        - <ip-address>
        - --bigip-username
        - <user-name>
        - --bigip-password
        - <password>
        - --log-level
        - DEBUG
        - --insecure
        - --controller-mode=openshift
        - --route-spec-configmap=kube-system/global-spec-config
        - --route-label=systest
        - --pool-member-type
        - cluster
        - --cis-type=primary
        command:
        - /app/bin/k8s-bigip-ctlr
        image: <image-name>
```

Note: Update the ```cis-type``` to *secondary* for secondary CIS deployment.

### extended ConfigMap Parameters

#### multiClusterConfigs Parameters

| Parameter   | Required  | Description                                                               | Default | Examples                |
|-------------|-----------|---------------------------------------------------------------------------|---------|-------------------------|
| clusterName | Mandatory | Name of the cluster                                                       | -       | cluster1                |
| secret      | Mandatory | Name of the secret created for kubeconfig (format: namespace/secret-name) | -       | test/secret-kubeconfig1 |



#### highAvailabilityClusterConfigs Parameters

| Parameter              | Required  | Description                                                             | Default | Examples                  |
|------------------------|-----------|-------------------------------------------------------------------------|---------|---------------------------|
| mode                   | Optional  | Type of high availability mode                                          | -       | -                         |
| primaryClusterEndPoint | Mandatory | Endpoint to check health of primary cluster                             | -       | http://10.145.72.114:8001 |
| probeInterval          | Optional  | Time interval between health check (in seconds)                         | 60      | 30                        |
| retryInterval          | Optional  | Time interval between recheck when primary cluster is down (in seconds) | 15      | 3                         |
| primaryCluster         | Mandatory | Primary cluster config                                                  | -       | -                         |
| secondaryCluster       | Mandatory | Secondary cluster config                                                | -       | -                         |


##### mode Parameters
| Parameter | Required | Description                                     | Default | Examples |
|-----------|----------|-------------------------------------------------|---------|----------|
| type      | Optional | Type of high availability mode (active/standby) | standby | active   |

Specifies whether the HA cluster is configured with active mode or standby mode
* If mode Type: active, CIS fetches service from both the HA clusters whenever it's referenced in Route Spec.
* If mode Type: standby (default), CIS fetches service from only the local cluster whenever it's referenced in a Route Spec.


##### primaryCluster/secondaryCluster Parameters

| Parameter   | Required  | Description                                                               | Default | Examples                |
|-------------|-----------|---------------------------------------------------------------------------|---------|-------------------------|
| clusterName | Mandatory | Name of the cluster                                                       | -       | cluster1                |
| secret      | Mandatory | Name of the secret created for kubeconfig (format: namespace/secret-name) | -       | test/secret-kubeconfig1 |


**Note**: In order to run CIS in high availability mode cis-type parameter (primary/secondary) needs to be set in the CIS deployment arguments.
* It's recommended to provide both primaryCluster and secondaryCluster configs in the extendedConfigMap.

##### PrimaryCluster Endpoint
 
Health probe parameters are provided in highAvailabilityClusterConfigs in extended configmap, help ensure high availability of CIS as the CIS running in secondary cluster continuously monitors the health of primary cluster, if it's down then the secondary CIS takes the responsibility of posting declarations to BIG-IP.
**Note**: primaryClusterEndPoint is a mandatory parameter if CIS is intended to run in multiCluster HA mode. If this is not specified secondary CIS will not run.


### Route Annotation for MultiClusterServices
Services running in any other Openshift clusters apart from the HA cluster pair can be referenced in the route annotations as mentioned below:
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

#### Route Annotation Parameters

| Parameter   | Required  | Description                                             | Default | Examples |
|-------------|-----------|---------------------------------------------------------|---------|----------|
| clusterName | Mandatory | Name of the cluster                                     | -       | cluster1 |
| svcName     | Mandatory | Name of the service                                     | -       | svc-1    |
| namespace   | Mandatory | Namespace where the service is created                  | -       | test     |
| port        | Optional  | port of the service  (for named port use string value ) | -       | 80       |


## Known issues
* Multi cluster feature doesn't work with CIS running in cluster mode(as of now).

## FAQ

### Is extended configMap mandatory for multiCluster support?
Yes. Multi cluster support only works with extended configmap.

### How do you add a new cluster?
To add a new cluster first customer has to create a kube-config file with read only permission. And then create a Kubernetes secret using the kube-config file. Then he can refer this in secret in extended configmap to add the new cluster.
CIS dynamically reads the new kubeconfig of the new cluster and starts listening to the services and endpoints in the new cluster when a route refers this new cluster.

### Where do you manage the manifest or Configuration Objects like Routes, Configmaps etc.?
Manifests or Configuration objects are managed centralized in Primary Cluster and if HA is desired the same manifests are expected to be in Secondary Cluster.

### What are the supported CNIs?
Currently only nodeport mode is supported.

### What kind of clusters are supported?
CIS supports Hybrid Cloud, any public Cloud providers like AWS, Azure, GCP , On-Prem, VmWare Tanzu etc. which is in same network/datacenter and can communicate with each other. 

### How does CIS start as a secondary Cluster?
CIS recognizes as Secondary when it starts with a deployment parameter i.e. --cis-type=secondary

### How does Secondary CIS learn about the Primary Cluster endpoint state in HA mode?
Both the CIS will communicate with both K8s API servers and prepares the AS3 declaration, but the secondary CIS only sends the declaration when the Primary cluster's health probe fails. As soon as primary cluster comes up, secondary CIS stops sending the declaration.

### What kind of permission is required for HA or standalone deployment of CIS?
No RBAC change for CIS deployment with multiCluster support. Only additional kube-config configuration with read only permission is required to access the endpoints from external cluster.

### What kind of permission is required to access external clusters (apart from HA and standalone)?
CIS requires read-only permission in Kubeconfig of external clusters to access resources like Pods/Services/Endpoints/Nodes.

### Can CIS manage multiple BIGIPs?
No. CIS can manage only Standalone BIGIP or HA BIGIP. In other words, CIS acts as a single point of BIGIP Orchestrator and supports MultiCluster.
