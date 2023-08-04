# OpenShift/Kubernetes Multi-Cluster Preview

This page documents a new feature in CIS for Multi-Cluster. This is a preview release which supports limited features and is not recommended to use in production environments. To provide feedback on Container Ingress Services or this documentation, please file a [GitHub Issue](https://github.com/F5Networks/k8s-bigip-ctlr/issues)

## Contents

[Overview](#overview)

[Topologies](#topologies)

[Configuration](#configuration)

[ExtendedSpecConfigMap](#extendedspecconfigmap)

[Examples](#examples)

[Known Issues](#known-issues)

[FAQ](#faq)


## Overview

Multi-Cluster Support in CIS allows users to expose multiple apps spread across OpenShift/Kubernetes clusters using a single BIG-IP Virtual Server. An app can be deployed different OpenShift clusters exposing them using a route resource. Using a Multi-Cluster implementation the CIS can be deployed in a HA topology, or Standalone CIS, to expose the apps spread across OpenShift clusters.


**Note**: 
* CIS supports processing of routes in traditional way as well as with NextGen Controller and with Multi-Cluster support.
* Currently, only nodePort is supported.

## Prerequisites
* Cluster node, where CIS is deployed, should be able to reach the API server of all OpenShift/Kubernetes clusters.
* extendedConfigMap needs to be created to run CIS in Multi-Cluster mode.
* kube-config files for each cluster should be available for CIS to access resources such as Pods/Services/Endpoints/Nodes.

## Topologies

### Standalone CIS

In a Standalone deployment of CIS, CIS is only deployed in one cluster, then create a route resource with a Multi-Cluster annotation to expose the apps in different OpenShift clusters.

![architecture](images/standaloneMultiCluster.png)

Below is the sample Multi-Cluster Config in an Extended Global ConfigMap.
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
  * A pair of High Availability OpenShift/Kubernetes clusters should be available, which have the same applications running in both clusters.
  * HealthCheck endpoint should be available to check the health of the primary cluster. Currently, TCP/HTTP Health endpoints are supported.


In HA deployment of CIS, CIS needs to be deployed in both the primary and secondary cluster. Also, the same extendedConfigMap needs to be deployed in both the primary and secondary cluster. 
CIS will look for the same service name in both primary and secondary clusters to expose the application via routes. Additionally, a Multi-Cluster annotation is created in the route definition exposing the applications in the other clusters.

Deploying CIS HA in Two Modes:
 * active-active and active-standby mode are used in case of CIS running in High Availability mode.
 * Based on the provided value the CIS running on Primary cluster decides whether to monitor the workloads running on Secondary Cluster or not.
 * In case of active-active mode CIS running on Primary cluster updates the pool members for Virtual Servers from both the clusters those are part of HA Cluster(Primary and Secondary Clusters) as well as pool members from all other remotely monitored clusters.
 * Whereas in case of active-standby mode CIS running on Primary cluster updates the pool members for Virtual Servers only from Primary Cluster and from all the other remotely monitored clusters except Secondary cluster.
 * However, in case the Primary cluster is down and CIS on the Secondary cluster has taken control then pool member from the Secondary Cluster as well as all other remotely monitored clusters are populated for the Virtual Servers irrespective of the value of HA mode.

**Note:**
 * Additionally, there is another supported mode called "ratio", in which pool members from all the Kubernetes/Openshift clusters are update for the Virtual Server, however the traffic distribution is done based on the ratio values defined for each cluster.
 * Ratio doesn't require CIS to be running in HA environment. It is supported in both CIS HA and non-HA environment.

Below is a tabular representation of the scenarios mentioned above:

###### When Primary Cluster is healthy and CIS is running on it

| HA Mode values | Primary Cluster Pool Members | Secondary Cluster Pool Members | Other remotely monitored clusters Pool Members | Traffic distribution based on ratio |
|----------------|------------------------------|--------------------------------|------------------------------------------------|-------------------------------------|
| active-active  | Yes                          | Yes                            | Yes                                            | No                                  |
| active-standby | Yes                          | No                             | Yes                                            | No                                  |
| ratio          | Yes                          | Yes                            | Yes                                            | Yes                                 |


###### When Primary Cluster is down, which means CIS in Secondary cluster has the control

| HA Mode values | Primary Cluster Pool Members | Secondary Cluster Pool Members | Other remotely monitored clusters Pool Members | Traffic distribution based on ratio |
|----------------|------------------------------|--------------------------------|------------------------------------------------|-------------------------------------|
| active-active  | No                           | Yes                            | Yes                                            | No                                  |
| active-standby | No                           | Yes                            | Yes                                            | No                                  |
| ratio          | Yes                          | Yes                            | Yes                                            | Yes                                 |

![architecture](images/haMultiCluster.png)

Below is the sample Multi-Cluster Configs with HA in Extended Global ConfigMap.
```
  extendedSpec: |
    mode: active-active       -----------------------------------|---->  HA Mode              |
    highAvailabilityCIS:   --------------------------------------|----------------------------|
      primaryEndPoint: http://10.145.72.114:8001                 |                            |
      probeInterval: 30                                          |                            |
      retryInterval: 3                                           |                            |
      primaryCluster:                                            |---> Cluster configs for    |
        clusterName: cluster1                                    |     High availability      |
        secret: default/kubeconfig1                              |     clusters               |---> Multi-Cluster configs
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

Below is the sample Multi-Cluster Configs with HA and Ratio in Extended Global ConfigMap.
```
  extendedSpec: |
    mode: ratio        ------------------------------------------|----------------------------|
    localClusterRatio: 4                                         |                            |
    highAvailabilityCIS:   --------------------------------------|                            |
      primaryEndPoint: http://10.145.72.114:8001                 |                            |
      probeInterval: 30                                          |                            |
      retryInterval: 3                                           |                            |
      primaryCluster:                                            |---> Cluster configs for    |
        clusterName: cluster1                                    |     High availability      |
        secret: default/kubeconfig1                              |     clusters               |---> Multi-Cluster configs
        ratio: 3                                                 |                            |
      secondaryCluster:                                          |                            |
        clusterName: cluster2                                    |                            |
        secret: default/kubeconfig2                              |                            |
        ratio: 2                                                 |                            |
    multiClusterConfigs:    -------------------------------------|                            |
    - clusterName: cluster3                                      |                            |
      secret: default/kubeconfig3                                |---> Cluster configs for    |
      ratio: 2                                                   |     all other clusters     |
    - clusterName: cluster4                                      |     except HA clusters     |
      secret: default/kubeconfig4                                |                            |
    - clusterName: cluster5                                      |                            |
      secret: default/kubeconfig5                                |                            |  
      ratio: 1                     ------------------------------|----------------------------|
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

If you are using the High Availability setup with Multi-Cluster, specify the ```--cis-type``` parameter to define the primary and secondary cluster:


| Parameter | Type   | Required | Description                                                                                  | Allowed Values       |
|-----------|--------|----------|----------------------------------------------------------------------------------------------|----------------------|
| cis-type  | String | Optional | Specify whether CIS is run as primary or secondary in the case of a high availability setup. | primary or secondary |

Following is the sample deployment for primary CIS deployment:

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

**Note:** Update the ```cis-type``` to *secondary* for a secondary CIS deployment.

### extended ConfigMap Parameters

#### multiClusterConfigs Parameters

| Parameter   | Type   | Required  | Description                                                               | Default | Examples                |
|-------------|--------|-----------|---------------------------------------------------------------------------|---------|-------------------------|
| clusterName | String | Mandatory | Name of the cluster                                                       | -       | cluster1                |
| secret      | String | Mandatory | Name of the secret created for kubeconfig (format: namespace/secret-name) | -       | test/secret-kubeconfig1 |

**Note:** Avoid specifying HA cluster(Primary/Secondary cluster) configs in multiClusterConfigs.

#### High Availability Mode (Optional parameter)
| Parameter              | Type    | Required  | Description                                                         | Default        | Examples       |
|------------------------|---------|-----------|---------------------------------------------------------------------|----------------|----------------|
| mode                   | Object  | Optional  | Type of high availability mode (active-active/active-standby/ratio) | active-standby | active-active  |

Specifies whether the CIS HA cluster is configured with active-active mode, active-standby mode or ratio mode.
* If mode Type: active-active, CIS fetches service from both the HA clusters whenever it's referenced in Route Spec.
* If mode Type: active-standby (default), CIS fetches service from only the local cluster whenever it's referenced in a Route Spec.
* If mode Type: ratio, CIS works in active-active mode and, it splits traffic according to the ratio specified for each cluster.

#### Local cluster ratio (Optional parameter)
| Parameter              | Type | Required  | Description                                                                                               | Default | Examples |
|------------------------|------|-----------|-----------------------------------------------------------------------------------------------------------|---------|----------|
| localClusterRatio      | Int  | Optional  | Ratio for the local cluster where CIS is running(specify only when using ratio in CIS non-HA environment) | 1       | 3        |
**Note:** It is not needed in case of using ratio in CIS HA environment, as ratio of Primary cluster does the same thing. If specified in this scenario then it will be ignored.

#### highAvailabilityCIS Parameters

| Parameter              | Type    | Required  | Description                                                             | Default | Examples                  |
|------------------------|---------|-----------|-------------------------------------------------------------------------|---------|---------------------------|
| primaryClusterEndPoint | String  | Mandatory | Endpoint to check health of primary cluster                             | -       | http://10.145.72.114:8001 |
| probeInterval          | Integer | Optional  | Time interval between health check (in seconds)                         | 60      | 30                        |
| retryInterval          | Integer | Optional  | Time interval between recheck when primary cluster is down (in seconds) | 15      | 3                         |
| primaryCluster         | Object  | Mandatory | Primary cluster config                                                  | -       | -                         |
| secondaryCluster       | Object  | Mandatory | Secondary cluster config                                                | -       | -                         |


##### primaryCluster/secondaryCluster Parameters

| Parameter   | Type   | Required  | Description                                                               | Default | Examples                |
|-------------|--------|-----------|---------------------------------------------------------------------------|---------|-------------------------|
| clusterName | String | Mandatory | Name of the cluster                                                       | -       | cluster1                |
| secret      | String | Mandatory | Name of the secret created for kubeconfig (format: namespace/secret-name) | -       | test/secret-kubeconfig1 |
| ratio       | int    | Optional  | Ratio at which the traffic has to be distributed over clusters            | 1       | 3                       |


**Note**: In order to run CIS in high availability mode, cis-type parameter (primary/secondary) needs to be set in the CIS deployment arguments.
* It's recommended to provide both primaryCluster and secondaryCluster configs in the extendedConfigMap.
* If no traffic has to be forwarded to a specific cluster then set the ratio field to 0.

##### CIS Primary Cluster Endpoint
 
Health probe parameters are provided in highAvailabilityCIS in extended configmap, helping to ensure high availability of CIS. CIS running in secondary cluster continuously monitors the health of the primary cluster. If it's down, then the secondary CIS takes the responsibility of posting declarations to BIG-IP.

**Note**: primaryEndPoint is a mandatory parameter if CIS is intended to run in Multi-Cluster HA mode. If this is not specified the secondary CIS will not run.


### Route Annotation for Multi-ClusterServices
Services running in any other OpenShift clusters, apart from the HA cluster pair, can be referenced in the route annotations as mentioned below:
```
virtual-server.f5.com/multiClusterServices: 
'[
     {
         "clusterName": "cluster2", 
         "serviceName": "svc-pytest-foo-1-com",
         "namespace": "foo", 
         "port": 80,
         "weight": 30,
     }
]'
```
**Note**: _weight_ needs to be specified onlyonly in A/B scenario
### Virutal Server Pool with Multi-ClusterServices
Services running in any other OpenShift/Kubernetes clusters, apart from the HA cluster pair, can be referenced in the VS Pool as mentioned below:
```
  pools:
  - path: /tea
    serviceNamespace: tea
    service: svc-2
    servicePort: 80
    extendedServiceReferences:
    - clusterName: cluster2
      namespace: ns1
      port: 8080
      serviceName: svc-1
    - clusterName: cluster3
      namespace: ns2
      port: 80
      serviceName: svc-ext-1
```

### Transport Server Pool with Multi-ClusterServices
Services running in any other OpenShift/Kubernetes clusters, apart from the HA cluster pair, can be referenced in the TS Pool as mentioned below:
```
  pool:
    service: svc-1
    servicePort: 8181
    extendedServiceReferences:
    - clusterName: cluster2
      serviceName: svc-1
      namespace: ns1
      port: 8181
    - clusterName: cluster3
      serviceName: svc-ext-1
      namespace: ns2
      port: 8282
```
#### Route Annotation / VS or TS MultiClusterServices Parameters

| Parameter   | Type       | Required   | Description                                             | Default | Examples |
|-------------|------------|------------|---------------------------------------------------------|---------|----------|
| clusterName | String     | Mandatory  | Name of the cluster                                     | -       | cluster1 |
| serviceName | String     | Mandatory  | Name of the service                                     | -       | svc-1    |
| namespace   | String     | Mandatory  | Namespace where the service is created                  | -       | test     |
| port        | String/Int | Mandatory  | port of the service  (for named port use string value ) | -       | 80       |
| weight      | Int        | Optional   | weight to be used for traffic splitting                 | 0       | 20       |

### Cluster wise Ratio for traffic distribution
CIS supports distribution of traffic across clusters as per the ratio configured for each cluster in the extended ConfigMap.<br>
It works even along with A/B where different weights are defined for each service. In such a case the ratio of traffic 
distribution is computed taking into consideration both the service weights and cluster ratio.<br>
However, the ratio of the clusters those haven't hosted any services linked to the concerned route are not taken into consideration 
while computing the final ratio.<br>
**Note:** Cluster wise ratio for traffic distribution is supported in HA as well as non-HA CIS environment.

## Known issues
* Multi-Cluster feature doesn't work with CIS running in cluster mode, as of this time.

## FAQ

### Is extended configMap mandatory for Multi-Cluster support?
Yes. Multi-Cluster support only works with extended configmap.

### How do you add a new cluster?
To add a new cluster, create a kube-config file with read only permissions. Then create a Kubernetes secret using the kube-config file. Refer this in secret in the extended ConfigMap to add the new cluster.
CIS dynamically reads the new kube-config of the new cluster and starts listening to the services and endpoints in the new cluster when a route refers this new cluster.

### Where do you manage the manifest or Configuration Objects like Routes, Configmaps etc.?
Manifests or Configuration objects are managed centralized in Primary Cluster and if HA is desired the same manifests are expected to be in Secondary Cluster.

### What are the supported CNIs?
Currently only NodePort mode is supported.

### What kind of clusters are supported?
CIS supports Hybrid Cloud, any public Cloud providers such as; AWS, Azure, GCP, On-Prem, VmWare, Tanzu etc. which is in same network/datacenter and can communicate with each other. 

### How does CIS start as a secondary Cluster?
CIS recognizes as Secondary when it starts with a deployment parameter i.e. --cis-type=secondary

### How does Secondary CIS learn about the Primary Cluster endpoint state in HA mode?
Both of the CIS will communicate with both K8s API servers and prepares the AS3 declaration, but the secondary CIS only sends the declaration when the Primary cluster's health probe fails. As soon as primary cluster comes up, secondary CIS stops sending the declaration.

### What kind of permission is required for HA or StandAlone deployment of CIS?
No RBAC change for CIS deployment with multiCluster support. Only additional kube-config configuration with read only permission is required to access the endpoints from external cluster.

### What kind of permission is required to access external clusters (apart from HA and StandAlone)?
CIS requires read-only permission in Kubeconfig of external clusters to access resources like Pods/Services/Endpoints/Nodes.

### Can CIS manage multiple BIG-IPs?
No. CIS can manage only Standalone BIG-IP or HA BIG-IP. In other words, CIS acts as a single point of BIG-IP Orchestrator and supports Multi-Cluster.

### Is traffic splitting with cluster ratio supported?
Yes. CIS supports traffic splitting as per the ratio specified for each cluster and also works with A/B as well.

