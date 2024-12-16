# OpenShift/Kubernetes Multi-Cluster

This page documents the multi cluster support in CIS. 

## Contents

[Overview](#overview)

[Topologies](#topologies)

[Configuration](#configuration)

[FAQ](#faq)


## Overview

Multi-Cluster Support in CIS allows users to expose multiple apps spread across OpenShift/Kubernetes clusters using a single BIG-IP Virtual Server. An app can be deployed in different OpenShift/Kubernetes clusters exposing them using a ServiceTypeLB/Route/VS/TS CR resource. Using a Multi-Cluster implementation the CIS can be deployed in a HA topology, or Standalone CIS, to expose the apps spread across OpenShift/Kubernetes clusters.


**Note**:
* CIS supports processing of routes in traditional way as well as with NextGen Controller and with Multi-Cluster support.
* At present, nodePort mode is supported and Cluster mode is available with static route configuration on BIGIP(No tunnels)

## Prerequisites
* Cluster node, where CIS is deployed, should be able to reach the API server of all OpenShift/Kubernetes clusters.
* ExtendedConfigMap needs to be created to run CIS in Multi-Cluster mode.
* Kube-config files for each cluster should be available for CIS to access resources such as Pods/Services/Endpoints/Nodes.

## Topologies

### Standalone CIS

* In a Standalone deployment of CIS, CIS is only deployed in one cluster, 
* There are two modes supported in the Standalone CIS, namely default and ratio.
  * The default mode is supported with VS/TS CRs, routes and ServiceType LB. See [Documentation](default-mode/README.md).
  * The ratio mode is supported with VS/TS CRs and routes.See [Documentation](non-default-mode/README.md#ratio-mode).

![architecture](images/standaloneMultiCluster.png)

### High Availability CIS

#### Prerequisites
* A pair of High Availability OpenShift/Kubernetes clusters should be available, which may have the same applications running in both clusters.
* HealthCheck endpoint should be available to check the health of the primary cluster. Currently, TCP/HTTP Health endpoints are supported.


* In HA deployment of CIS, CIS needs to be deployed in both the primary and secondary cluster. Also, the same extendedConfigMap needs to be deployed in both the primary and secondary cluster.
* There are three modes supported in the High Availability CIS, namely default, active-active and ratio.
  * The default mode is supported with VS/TS CRs, routes and ServiceType LB. See [Documentation](default-mode/README.md).
  * The Active-Active mode is supported with VS/TS CRs and routes.See [Documentation](non-default-mode/README.md#active-active-mode).
  * The ratio mode is supported with VS/TS CRs and routes.See [Documentation](non-default-mode/README.md#ratio-mode).

**Note**:
* For HA mode [namely default, active-active, ratio], CIS monitored resource manifests(such as routes, CRDs, extendedConfigmaps, multiCluster serviceTypeLB) must be available in both the clusters.
* The CIS monitored resource manifests should be identical on both primary and Secondary Clusters
* So, In case of CIS failover, CIS on Secondary Cluster will take control and will start processing the CIS monitored resource manifests.
* CIS on Secondary Cluster will not process the CIS monitored resource manifests if they are not available in Secondary Cluster.
* Make sure to have identical resource manifests in both the clusters to avoid any issues during CIS fail-over.

    
![architecture](images/haMultiCluster.png)

## Configuration

### CIS Deployment Parameter

If you are using multi-cluster mode, ```--multi-cluster-mode``` and ```--local-cluster-name``` are required parameters.


| Parameter               | Type   | Required | Description                                                                                                    | Allowed Values                                      |
|-------------------------|--------|----------|----------------------------------------------------------------------------------------------------------------|-----------------------------------------------------|
| multi-cluster-mode      | String | Required | Specify whether CIS is running standalone or as primary/secondary in the case of a high availability topology. | standalone or primary or secondary                  |
| local-cluster-name      | String | Required | Specify the cluster name where CIS is running.                                                                 | valid cluster name defined in the extendedConfigMap |
| extended-spec-configmap | String | Required | extendedSpecConfigMap is required to configure the multi-cluster configuration                                 | <namespace>/<config-map-name>                       |

**Note**: 

* Here **standalone** refers to standalone topology of CIS deployment, See [Standalone CIS](#standalone-cis).

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
        - --extended-spec-configmap=kube-system/extended-spec-config
        - --route-label=systest
        - --pool-member-type
        - nodeport
        - --multi-cluster-mode=primary
        - --local-cluster-name=cluster1
        command:
        - /app/bin/k8s-bigip-ctlr
        image: <image-name>
```

**Note:**
1. Update the ```multi-cluster-mode``` to *secondary* for secondary CIS deployment in high availablility topology, See [High Availability CIS](#high-availability-cis).
2. Update the ```multi-cluster-mode``` to *standalone* for standalone topology, See [Standalone CIS](#standalone-cis).
3. Update the ```local-cluster-name``` to the cluster name where CIS is running.

### Extended ConfigMap

* See How to configure the extendedConfigMap in default mode in standalone topology, [Documentation](default-mode/README.md#configuring-extendedconfigmapforstandalone).
* See How to configure the extendedConfigMap in default mode in high availability topology, [Documentation](default-mode/README.md#configuring-extendedconfigmapforhighavailability).
* See How to configure the extendedConfigMap in active-active mode, [Documentation](non-default-mode/README.md#configuring-extendedconfigmapforstandalone).
* See How to configure the extendedConfigMap in ratio mode in standalone topology, [Documentation](non-default-mode/README.md#configuring-extended-configmap-for-ratio-mode-standalone-cis).
* See How to configure the extendedConfigMap in ratio mode in high availability topology, [Documentation](non-default-mode/README.md#configuring-extended-configmap-for-ratio-mode-high-availability-cis).

### VS CR Support
* See How to configure the VS CR in default mode [Documentation](default-mode/README.md#virtual-server-support).
* See How to configure the VS CR in active-active and ratio mode [Documentation](non-default-mode/README.md#virtual-server-support).

### TS CR Support
* See How to configure the TS CR in default mode [Documentation](default-mode/README.md#transport-server-support).
* See How to configure the TS CR in active-active and ratio mode [Documentation](non-default-mode/README.md#transport-server-support).

### Routes Support
* See How to configure the routes in default mode [Documentation](default-mode/README.md#routes-support).
* See How to configure the routes in active-active and ratio mode [Documentation](non-default-mode/README.md#routes-support).

### ServiceTypeLB Support
* See How to configure the ServiceTypeLB in default mode [Documentation](default-mode/README.md#service-type-load-balancer-support).
* ServiceTypeLB is not supported in active-active and ratio mode.

## FAQ

### Is --multi-cluster-mode is a required parameter for Multi-Cluster support?
Yes. Multi-Cluster support only works if --multi-cluster-mode is defined in CIS deployment.

### Is extended configMap mandatory for Multi-Cluster support?
Yes. Multi-Cluster support only works with extended configmap.

### Is local-cluster-name mandatory for Multi-Cluster support?
Yes. Multi-Cluster support only works if --local-cluster-name is defined in CIS deployment.

### Does extended configmap update require CIS restart?
No. It's recommended to restart CIS if any HA configuration or external cluster configurations are updated in extended Configmap. However, CIS restart is not required when updating ratio in the extended Configmap.

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

### Does Secondary CIS require resource manifests existing in Primary Cluster?
Yes. CIS on Secondary Cluster will not process the CIS monitored resource manifests[NextGen Routes, CRDs, ServiveTypeLB, extendedConfigmap] if they are not available in Primary Cluster.
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

### Are the custom resources like TS and VS are same in all modes(default, active-active, ratio)?
No, Custom resources like TS and VS are different in default mode and non-default mode. See [Documentation](default-mode/README.md) for default mode and [Documentation](non-default-mode/README.md) for active-active and ratio mode.

### Are the routes supported in all modes(default, active-active, ratio)?
Yes, Routes are supported in all modes. 
See [Documentation](non-default-mode/README.md#routes-support) for active-active and ratio mode. 
See [Documentation](default-mode/README.md#routes-support) for default mode.

### Are policy CR supported in all modes(default, active-active, ratio)?
Yes, Policy CR is supported in all modes same as non-multi-cluster mode.
