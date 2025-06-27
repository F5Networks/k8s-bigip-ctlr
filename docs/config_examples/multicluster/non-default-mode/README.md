# Ratio and Active-Active mode in Multi-Cluster

This page documents the ratio and active-active mode for multi cluster support in CIS.

## Contents

[Overview](#overview)

[Active-Active Mode](#active-active-mode)

[Ratio Mode](#ratio-mode)

[Supported ExtendedConfigMap Parameters](#extended-configmap-parameters)

[Transport Server Support](#transport-server-support)

[Virtual Server Support](#virtual-server-support)

[Routes Support](#routes-support)

[Known Issues](#known-issues)

[FAQ](#faq)


## Overview

CIS supports ratio and active-active modes as well for multi-cluster. The active-active mode distribute the traffic equally to all the clusters, However the ratio mode is used to distribute traffic across multiple clusters based on the ratio defined for each cluster. 

## Active-Active Mode
* In case of active-active mode CIS running on Primary cluster updates the pool members for Virtual Servers from both the clusters those are part of HA Cluster(Primary and Secondary Clusters) as well as pool members from all other remotely monitored clusters.
* However, in case the Primary cluster is down and CIS on the Secondary cluster has taken control then pool member from the Secondary Cluster as well as all other remotely monitored clusters are populated for the Virtual Servers irrespective of the value of HA mode.

**Note**:
* For HA mode [namely default, active-active, ratio], CIS monitored resource manifests(such as routes, CRDs, extendedConfigmaps) must be available in both the clusters.
* The CIS monitored resource manifests must be identical on both primary and Secondary Clusters
* So, In case of CIS fail-over, CIS on Secondary Cluster will take control and will start processing the CIS monitored resource manifests.
* CIS on Secondary Cluster will not process the CIS monitored resource manifests if they are not available in Secondary Cluster.
* MakeSure to have identical resource manifests in both the clusters to avoid any issues during CIS fail-over.

![architecture](../images/haMultiCluster.png)


### Configuring Extended ConfigMap for Active-Active High Availability CIS
Below is the sample Multi-Cluster Configs with HA in Extended ConfigMap.
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
    externalClustersConfig:    -------------------------------------|                            |
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
**Note**: extendedRouteSpec is only applicable in case of openshift route resources not for CRD resources.

### Configuring Extended ConfigMap for Active-Active High Availability CIS with Cluster AdminState
Below is the sample Multi-Cluster Configs with HA and cluster AdminState in Extended ConfigMap.
```
  extendedSpec: |
    mode: active-active    --------------------------------------|----------------------------|
    highAvailabilityCIS:   --------------------------------------|                            |
      primaryEndPoint: http://10.145.72.114:8001                 |                            |
      probeInterval: 30                                          |                            |
      retryInterval: 3                                           |                            |
      primaryCluster:                                            |---> Cluster configs for    |
        clusterName: cluster1                                    |     High availability      |
        secret: default/kubeconfig1                              |     clusters               |---> Multi-Cluster configs
      secondaryCluster:                                          |                            |
        clusterName: cluster2                                    |                            |
        secret: default/kubeconfig2                              |                            |
        adminState: enable                                       |                            |
    externalClustersConfig:    ----------------------------------|                            |
    - clusterName: cluster3                                      |                            |
      secret: default/kubeconfig3                                |---> Cluster configs for    |
      adminState: disable                                        |     all other clusters     |
    - clusterName: cluster4                                      |     except HA clusters     |
      secret: default/kubeconfig4                                |                            |
    - clusterName: cluster5                                      |                            |
      secret: default/kubeconfig5                                |                            |  
      adminState: offline          ------------------------------|----------------------------|
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
**Note**: extendedRouteSpec is only applicable in case of openshift route resources not for CRD resources.


## Ratio Mode
Ratio mode is a feature in CIS that allows users to distribute traffic across multiple clusters based on the ratio defined for each cluster. This feature is supported in both CIS HA and standalone environment. In ratio mode, CIS works in active-active mode and, it splits traffic according to the ratio values defined for each cluster.

### Configuring Extended ConfigMap for Ratio Mode Standalone CIS
Below is the sample Multi-Cluster Config in an Extended ConfigMap with ratio mode in standalone topology.
```
  extendedSpec: |
    mode: ratio
    localClusterRatio: 4                                         |                            |
    externalClustersConfig:    ----------------------------------|----------------------------|                            |
    - clusterName: cluster3                                      |                            |
      secret: default/kubeconfig3                                |---> Cluster configs for    |
      ratio: 3                                                   |     all clusters           |
    - clusterName: cluster4                                      |                            |
      secret: default/kubeconfig4                                |                            |
      ratio: 4                                                   |                            |
    - clusterName: cluster5                                      |                            |
      secret: default/kubeconfig5  ------------------------------|----------------------------|
      ratio: 5                                                   |                            |
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
**Note**: extendedRouteSpec is only applicable in case of openshift route resources not for CRD resources.

### Configuring Extended ConfigMap for Cluster AdminState in Ratio Mode Standalone CIS
Below is the sample Multi-Cluster Configs with standalone CIS and cluster AdminState in Extended ConfigMap.
```
  extendedSpec: |
    localClusterAdminState: disable  ----------------------------|AdminState for local cluster|
    externalClustersConfig:    ----------------------------------|----------------------------|
    - clusterName: cluster3                                      |                            |
      secret: default/kubeconfig3                                |---> Cluster configs for    |
      adminState: enable                                         |     all clusters           |
    - clusterName: cluster4                                      |                            |
      secret: default/kubeconfig4                                |                            |
    - clusterName: cluster5                                      |                            |
      secret: default/kubeconfig5                                |                            |  
      adminState: offline          ------------------------------|----------------------------|
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
**Note**: localClusterAdminState is only applicable in case of standalone CIS. It's ignored if specified in HA CIS mode.

### Configuring Extended ConfigMap for Ratio Mode High Availability CIS

Below is the sample Multi-Cluster Configs with HA and Ratio in Extended ConfigMap.
```
  extendedSpec: |
    mode: ratio        ------------------------------------------|----------------------------|
    highAvailabilityCIS:   --------------------------------------|                            |
      primaryEndPoint: http://10.145.72.114:8001                 |                            |
      probeInterval: 30                                          |                            |
      retryInterval: 3                                           |                            |
      primaryCluster:                                            |---> Cluster configs for    |
        clusterName: cluster1                                    |     High availability      |
        secret: default/kubeconfig1                              |     clusters               |---> Multi-Cluster configs
        ratio: 3                                                 |                            |
        adminState: enable                                       |                            |
      secondaryCluster:                                          |                            |
        clusterName: cluster2                                    |                            |
        secret: default/kubeconfig2                              |                            |
        ratio: 2                                                 |                            |
        adminState: enable                                       |     all other clusters     |
    externalClustersConfig:    ----------------------------------|                            |
    - clusterName: cluster3                                      |                            |
      secret: default/kubeconfig3                                |---> Cluster configs for    |
      ratio: 2                                                   |     all other clusters     |
      adminState: disable                                        |     except HA clusters     |
    - clusterName: cluster4                                      |                            |
      secret: default/kubeconfig4                                |                            |
    - clusterName: cluster5                                      |                            |
      secret: default/kubeconfig5                                |                            | 
      adminState: offline                                        |                            | 
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
**Note**: extendedRouteSpec is only applicable in case of openshift route resources not for CRD resources.

### Configuring Extended ConfigMap for Cluster AdminState in Ratio Mode High Availability CIS

```
  extendedSpec: |
    mode: ratio        ------------------------------------------|----------------------------|
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
    externalClustersConfig:    -------------------------------------|                            |
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

**Note**: extendedRouteSpec is only applicable in case of openshift route resources not for CRD resources.

### extended ConfigMap Parameters

**externalClustersConfig Parameters**

| Parameter   | Type   | Required  | Description                                                               | Default | Examples                |
|-------------|--------|-----------|---------------------------------------------------------------------------|---------|-------------------------|
| clusterName | String | Mandatory | Name of the cluster                                                       | -       | cluster1                |
| secret      | String | Mandatory | Name of the secret created for kubeconfig (format: namespace/secret-name) | -       | test/secret-kubeconfig1 |
| ratio       | int    | Optional  | Ratio at which the traffic has to be distributed over clusters            | 1       | 3                       |
| adminState  | String | Optional  | adminState can be used to disable/enable/offline/no-pool clusters         | enable  | disable                 |


Note: Avoid specifying HA cluster(Primary/Secondary cluster) configs in externalClustersConfig.

**Mode Parameter**

| Parameter | Type   | Required | Description                                          | Default | Examples |
|-----------|--------|----------|------------------------------------------------------|---------|----------|
| mode      | Object | Optional | Type of high availability mode (active-active/ratio) | default | default  |

Specifies whether the CIS HA cluster is configured with active-active mode, default mode or ratio mode.
* active-active: CIS fetches service from both the HA clusters whenever it's referenced in Route Spec.
* ratio: CIS works in active-active mode and, it splits traffic according to the ratio specified for each cluster.
* default: See Documentation for more [details](../default-mode/README.md)

**Local cluster ratio Parameter** 

| Parameter              | Type | Required  | Description                                                                                               | Default | Examples |
|------------------------|------|-----------|-----------------------------------------------------------------------------------------------------------|---------|----------|
| localClusterRatio      | Int  | Optional  | Ratio for the local cluster where CIS is running(specify only when using ratio in CIS non-HA environment) | 1       | 3        |

Note: It is not needed in case of using ratio in CIS HA environment, as ratio of Primary cluster does the same thing. If specified in this scenario then it will be ignored.

**highAvailabilityCIS Parameters** 

| Parameter        | Type    | Required  | Description                                                             | Default | Examples                  |
|------------------|---------|-----------|-------------------------------------------------------------------------|---------|---------------------------|
| primaryEndPoint  | String  | Mandatory | Endpoint to check health of primary cluster                             | -       | http://10.145.72.114:8001 |
| probeInterval    | Integer | Optional  | Time interval between health check (in seconds)                         | 60      | 30                        |
| retryInterval    | Integer | Optional  | Time interval between recheck when primary cluster is down (in seconds) | 15      | 3                         |
| primaryCluster   | Object  | Mandatory | Primary cluster config                                                  | -       | -                         |
| secondaryCluster | Object  | Mandatory | Secondary cluster config                                                | -       | -                         |

Health probe parameters are provided in highAvailabilityCIS in extended configmap, helping to ensure high availability of CIS. CIS running in secondary cluster continuously monitors the health of the primary cluster. If it's down, then the secondary CIS takes the responsibility of posting declarations to BIG-IP.

Note: The primaryEndPoint is a mandatory parameter if CIS is intended to run in Multi-Cluster HA mode. If this is not specified the secondary CIS will not run.


**primaryCluster/secondaryCluster Parameters**

| Parameter   | Type   | Required  | Description                                                               | Default | Examples                |
|-------------|--------|-----------|---------------------------------------------------------------------------|---------|-------------------------|
| clusterName | String | Mandatory | Name of the cluster                                                       | -       | cluster1                |
| secret      | String | Mandatory | Name of the secret created for kubeconfig (format: namespace/secret-name) | -       | test/secret-kubeconfig1 |
| ratio       | int    | Optional  | Ratio at which the traffic has to be distributed over clusters            | 1       | 3                       |
| adminState  | String | Optional  | adminState can be used to disable/enable/offline/no-pool clusters         | enable  | disable                 |


Note: In order to run CIS in high availability mode, multi-cluster-mode parameter (primary/secondary) needs to be set in the CIS deployment arguments.
* It's recommended to provide both primaryCluster and secondaryCluster configs in the extendedConfigMap.
* If no traffic has to be forwarded to a specific cluster then set the ratio field to 0.

### Transport Server Support
* CIS does the service and alternateBackend service discovery in all the clusters specified via the extended ConfigMap.
* See [Examples](transportServer)

### Virtual Server Support
* CIS does the service and alternateBackend service discovery in all the clusters specified via the extended ConfigMap.
* See [Examples](virtualServer)

### Routes Support
* If multiClusterServices annotation is not provided in the Route, then CIS will fetch the services from primary & secondary clusters and add the pool-members.
* If multiClusterServices annotation is provided in the Route, then CIS will fetch the services from the primary & secondary clusters as well as from the clusters mentioned in the annotation and add the pool-members.
* See Examples [here](routes)
* 
### Route Annotation for Multi-ClusterServices
Services running in any other OpenShift clusters, as mentioned below:
```
virtual-server.f5.com/multiClusterServices: 
'[
     {
         "clusterName": "cluster2", 
         "service": "svc-pytest-foo-1-com",
         "namespace": "foo", 
         "servicePort": 80,
         "weight": 30,
     }
]'
```

| Parameter   | Type       | Required   | Description                                             | Default | Examples |
|-------------|------------|------------|---------------------------------------------------------|---------|----------|
| clusterName | String     | Mandatory  | Name of the cluster                                     | -       | cluster1 |
| service     | String     | Mandatory  | Name of the service                                     | -       | svc-1    |
| namespace   | String     | Mandatory  | Namespace where the service is created                  | -       | test     |
| servicePort | String/Int | Mandatory  | port of the service  (for named port use string value ) | -       | 80       |
| weight      | Int        | Optional   | weight to be used for traffic splitting                 | 0       | 20       |

### Cluster wise Ratio for traffic distribution
CIS supports distribution of traffic across clusters as per the ratio configured for each cluster in the extended ConfigMap.<br>
It works even along with [A/B](#ab-or-alternate-backends) where different weights are defined for each service. In such a case the ratio of traffic 
distribution is computed taking into consideration both the service weights and cluster ratio.<br>
However, the ratio of the clusters those haven't hosted any services linked to the concerned route are not taken into consideration 
while computing the final ratio.<br>

**Note:** 
* Cluster wise ratio for traffic distribution is supported in HA as well as non-HA CIS environment.
* Ratio is only supported for NextGen Routes and Virtual and Transport Server CR.
* Setting cluster adminState in conjunction with cluster ratio will affect the overall traffic distribution across clusters.
  As the clusters marked as disable or offline will not receive traffic, so any ratio defined for these clusters will be rendered ineffective.
  Thus, in such a scenario it's recommended to set the cluster ratio to 0 for all the clusters marked with disable/offline.

### A/B or Alternate Backends
What it is?

* A/B or Alternate Backends is a deployment strategy that allows you to release a new version of an application (version B) to a subset of users, while the majority still uses the old version (version A).
* It helps in comparing two versions of a service or application (referred to as A and B) to determine which one performs better based on specific metrics, such as response time, error rates, or user engagement.
* It allows you to gradually release changes to a subset of users and gather data to make informed decisions about whether to fully roll out the new version.
* This services defined in Alternate Backends exist in either of the HA peer clusters or in both of the HA clusters. Since HA clusters usually hold similar configurations, ideally these services exist in both the HA clusters.

What it isn't?

* Services defined as Alternate Backends don't have to be created only in the other HA peer cluster(by other HA peer cluster it means if CIS is running in Primary cluster then Secondary cluster is the other HA peer cluster and vice versa).
* Alternate Backends are not primarily used for failover scenarios, however BIGIP does forward the traffic to any of the available backend service if any service goes down or fails health check.

### Cluster adminState to enable/disable/offline a cluster
adminState can be provided for a cluster to dictate the state of a particular cluster.
Supported values for adminState are [enable, disable, offline, no-pool]<br>
By default clusters are in enabled state.<br>
**adminState: enable**, all new connections are allowed to the pool members from the cluster.<br>
**adminState: disable**, all new connections except those which match an existing persistence session are not allowed for the pool members from the cluster.<br>
**adminState: offline**, no new connections are allowed to the pool members from the cluster, even if they match an existing persistence session.<br>
**adminState: no-pool**, in ratio mode, a service pool is not created for the affected cluster. For all other modes, pool members from the cluster are not added to the service pool. This configuration is helpful when we don't want to add pool or pool members from a particular cluster due to any reasons(for example cluster is under maintenance).<br>


**Note**:
* For HA mode [namely default, active-active, ratio], CIS monitored resource manifests(such as routes, CRDs, extendedConfigmaps) must be available in both the clusters.
* The CIS monitored resource manifests must be identical on both primary and Secondary Clusters
* So, In case of CIS failover, CIS on Secondary Cluster will take control and will start processing the CIS monitored resource manifests.
* CIS on Secondary Cluster will not process the CIS monitored resource manifests if they are not available in Secondary Cluster.
* MakeSure to have identical resource manifests in both the clusters to avoid any issues during CIS failover.


## Known issues
*  Pool members are not getting populated for extended service in ratio mode
*  CIS doesn't update pool members if service doesn't exist in primary cluster but exists in secondary cluster for Route.
*  CIS on start up in multiCluster mode, if any external cluster kube-api server is down/not reachable, CIS is struck and not processing any valid clusters config also.Workaround to remove unreachable cluster config from configmap and restart CIS
*  CIS fails to post declaration with VS with health monitors in ratio mode.Issue is observed intermittently
*  Route status is not updated in other HA cluster. For eg: Active Primary CIS cluster doesn't update the route status in Secondary HA cluster and vice-versa.

## FAQ

### Does extended configmap update require CIS restart?
No. It's recommended to restart CIS if any HA configuration or external cluster configurations are updated in extended Configmap. However CIS restart is not required when updating ratio in the extended Configmap.

### Does mode update require CIS restart?
Yes. CIS has to be restarted when there is a change in the mode. 

### How do you add a new cluster?
To add a new cluster, create a kube-config file with read only permissions. Then create a Kubernetes secret using the kube-config file. Refer this in secret in the extended ConfigMap to add the new cluster.
CIS dynamically reads the new kube-config of the new cluster and starts listening to the services and endpoints in the new cluster when a route refers this new cluster.

### Where do you manage the manifest or Configuration Objects like Routes, CRDs, ExtendedConfigmaps etc.?
Manifests or Configuration objects are managed centralized in Primary Cluster and if HA is desired the same manifests are expected to be in Secondary Cluster.

### What are the supported CNIs?
Currently, NodePort mode is supported.For cluster mode, static routing mode is supported to enable configuration of static routes on bigip for pod network subnets for direct routing from BIGIP to k8s Pods

### What kind of providers are supported?
CIS supports Hybrid Cloud, any public Cloud providers such as; AWS, Azure, GCP, On-Prem, VmWare, Tanzu etc. which is in same network/datacenter and can communicate with each other. 

### What kind of clusters are supported?
CIS multicluster solution is currently validated with openshift clusters and K8s clusters

### How does CIS start as a secondary Cluster?
CIS recognizes as Secondary when it starts with a deployment parameter i.e. --multi-cluster-mode=secondary

### How does Secondary CIS learn about the Primary Cluster endpoint state in HA mode?
Both of the CIS will communicate with both K8s API servers and prepares the AS3 declaration, but the secondary CIS only sends the declaration when the Primary cluster's health probe fails. As soon as primary cluster comes up, secondary CIS stops sending the declaration.

### What kind of permission is required for HA or StandAlone deployment of CIS?
No RBAC change for CIS deployment with multiCluster support. Only additional kube-config configuration with read only permission is required to access the endpoints from external cluster.

### What kind of permission is required to access external clusters (apart from HA and StandAlone)?
CIS requires read-only permission in Kubeconfig of external clusters to access resources like Pods/Services/Endpoints/Nodes.

### Can CIS manage multiple BIG-IPs?
No. CIS can manage only Standalone BIG-IP or HA BIG-IP. In other words, CIS acts as a single point of BIG-IP Orchestrator and supports Multi-Cluster.

### Is serviceTypeLBDiscovery supported for modes other than default mode?
No

### Is traffic splitting with cluster ratio supported?
Yes. CIS supports traffic splitting as per the ratio specified for each cluster and also works with [A/B](#ab-or-alternate-backends) as well.

### Is A/B supported in multiCluster mode?
Yes. CIS supports [A/B](#ab-or-alternate-backends) with active-active and ratio mode in multiCluster.

### Is A/B custom persistence supported in all the modes?
No. [A/B](#ab-or-alternate-backends) persistence is supported in ratio mode and pool member type as cluster.

### Does Secondary CIS require resource manifests existing in Primary Cluster?
Yes. CIS on Secondary Cluster will not process the CIS monitored resource manifests[NextGen Routes, CRDs, extendedConfigmap] if they are not available in Primary Cluster.
This is required in case of CIS failover, CIS on Secondary Cluster will take control and will start processing the CIS monitored resource manifests.
It is suggested to maintain identical CIS monitored resource manifests in both the clusters to avoid any issues during CIS failover.
This requirement is applicable in case of CIS HA mode [namely default, active-active, ratio].

### How to configure the primaryEndPoint in HA mode?
The primaryEndPoint is a mandatory parameter if CIS is intended to run in Multi-Cluster HA mode[namely default, active-active, ratio]. If this is not specified the secondary CIS will not run.
Secondary CIS will continuously monitor the health of the primary cluster based on the primaryEndPoint value. If it's down, then the secondary CIS takes the responsibility of posting declarations to BIG-IP.
Supported Protocols for the primaryEndPoint are HTTP and TCP.
Generally, it's suggested to use the primaryEndPoint as
  a) any available endpoint to check the health of the primary cluster.
  b) Primary CIS cluster's health check endpoint (/health) if accessible.
  c) Primary CIS cluster's kube-api server endpoint if accessible.
Response code 200 OK is expected from the primaryEndPoint in case of HTTP Protocol.
Successful TCP connection is expected from the primaryEndPoint in case of TCP Protocol.
Secondary CIS become active if the primaryEndPoint is not accessible.
PrimaryEndPoint is optional to configure for Primary CIS.
Note: Primary CIS will not monitor the health of the Secondary CIS cluster.

### How to configure the primaryEndPoint in Standalone mode?
The primaryEndPoint is not applicable in Standalone mode. It's only applicable in HA mode.

### How to use CIS /health endpoint to check the health of CIS?
Fetch the CIS PodIP and use it in the curl command as shown below from any of the cluster nodes:
```
curl  http://<CIS-PodIP>:8080/health
```
Response code 200 OK is expected from the CIS /health endpoint if kube-api server is accessible.
Example:
```
[root@cluster-1-worker0 ~]# curl http://10.244.1.213:8080/health
Ok[root@cluster-1-worker0 ~]# curl http://10.244.1.213:8080/health -v
* About to connect() to 10.244.1.213 port 8080 (#0)
*   Trying 10.244.1.213...
* Connected to 10.244.1.213 (10.244.1.213) port 8080 (#0)
> GET /health HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 10.244.1.213:8080
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Thu, 07 Dec 2023 08:28:57 GMT
< Content-Length: 2
< Content-Type: text/plain; charset=utf-8
< 
* Connection #0 to host 10.244.1.213 left intact
Ok[root@cluster-1-worker0 ~]#
```
where 10.244.1.213 is the CIS PodIP.

### How to configure multiClusterServices in Route annotation?
multiClusterServices is a Route annotation. Below is the sample Route annotation with multiClusterServices:
```
virtual-server.f5.com/multiClusterServices:
'[
     {
         "clusterName": "cluster2",
         "service": "svc-pytest-foo-1-com",
         "namespace": "foo",
         "servicePort": 80,
         "weight": 30,
     }
]'
```
where clusterName is the name of the cluster where the service is running, namespace is the namespace where the service is running, servicePort is the port of the service and service is the name of the service.
where cluster2 is the external cluster apart from the HA cluster pair.
Note: External Clusters doesn't need to install CIS

### Are policy CR supported in Active-Active and Ratio mode?
Yes, Policy CR is supported in all modes same as non-multi-cluster mode.
