# default mode in Multi-Cluster

This page documents the default mode for multi cluster support in CIS.

## Contents

[Overview](#overview)

[Default Mode](#default-mode)

[Supported ExtendedConfigMap Parameters](#extended-configmap-parameters)

[Transport Server Support](#transport-server-support)

[Virtual Server Support](#virtual-server-support)

[Routes Support](#routes-support)

[ServiceTypeLB Support](#service-type-load-balancer-support)

[Known Issues](#known-issues)

[FAQ](#faq)

## Default Mode

This is the default mode for multi-cluster support in CIS. This mode is supported with both standalone and HA deployments of CIS. 

In this mode, you need to explicitly define the list of services from all the clusters in the TS and VS CR that you want to expose through CIS.

This mode also supports the discovery of serviceType LB resources from external clusters including HA peer cluster. 

MultiCluster LoadBalancer services are also supported in this mode. Where you can expose the same serviceType LB from the multiple clusters.


#### Configuring extendedConfigMapForStandAlone

Below is the sample Multi-Cluster Config in an Extended ConfigMap with default mode in standalone topology.
```
  extendedSpec: |
    mode: default
    externalClustersConfig:    ----------------------------------|---------------------------------------------------|                            |
    - clusterName: cluster3                                      |                                                   |
      secret: default/kubeconfig3                                |---> Cluster configs for                           |
      serviceTypeLBDiscovery: true                               |---> CIS discovers the LB services in this cluster |
    - clusterName: cluster4                                      |     all  clusters                                 |
      secret: default/kubeconfig4                                |                                                   |
    - clusterName: cluster5                                      |                                                   |
      secret: default/kubeconfig5  ------------------------------|---------------------------------------------------|
```


#### Configuring extendedConfigMapForHighAvailability

Below is the sample Multi-Cluster Config in an Extended ConfigMap with default mode in high availability topology.

```
  extendedSpec: |
    mode: default        ----------------------------------------|----------------------------|
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
    externalClustersConfig:    ----------------------------------|                            |
    - clusterName: cluster3                                      |                            |
      secret: default/kubeconfig3                                |---> Cluster configs for    |
    - clusterName: cluster4                                      |     all other clusters     |
      secret: default/kubeconfig4                                |     except HA clusters     |
    - clusterName: cluster5                                      |                            |
      secret: default/kubeconfig5                                |                            |  
```


### extended ConfigMap Parameters

**externalClustersConfig Parameters**

| Parameter   | Type   | Required  | Description                                                               | Default | Examples                |
|-------------|--------|-----------|---------------------------------------------------------------------------|---------|-------------------------|
| clusterName | String | Mandatory | Name of the cluster                                                       | -       | cluster1                |
| secret      | String | Mandatory | Name of the secret created for kubeconfig (format: namespace/secret-name) | -       | test/secret-kubeconfig1 |


Note: Avoid specifying HA cluster(Primary/Secondary cluster) configs in externalClustersConfig.

**Mode Parameter**

| Parameter | Type   | Required | Description                                          | Default | Examples |
|-----------|--------|----------|------------------------------------------------------|---------|----------|
| mode      | Object | Optional | Type of high availability mode (active-active/ratio) | default | default  |

Specifies whether the CIS HA cluster is configured with active-active mode, default mode or ratio mode.
* active-active: CIS fetches service from both the HA clusters whenever it's referenced in Route Spec.
* ratio: CIS works in active-active mode and, it splits traffic according to the ratio specified for each cluster.
* default: See Documentation for more [details](../default-mode/README.md)

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


Note: In order to run CIS in high availability mode, multi-cluster-mode parameter (primary/secondary) needs to be set in the CIS deployment arguments.
* It's recommended to provide both primaryCluster and secondaryCluster configs in the extendedConfigMap.

### Transport Server Support
* CIS does not support the service and alternateBackend service parameters in this mode, you need to use the spec.Pool.multiClusterServices properties to define the services from all the clusters.
* See [Examples](transportServer)

### Virtual Server Support
* CIS does not support the service and alternateBackend service parameters in this mode, you need to use the spec.Pools[*].multiClusterServices properties to define the services from all the clusters.
* See [Examples](virtualServer)

### Routes Support
* default mode is currently not supported for Routes, please use active-active/active-standby/ratio mode


### Service Type Load Balancer Support
In multiCluster environment CIS offers following two solutions for supporting ServiceTypeLBs:

1) Non-multiCluster ServiceTypeLB - In this case, CIS will discover the ServiceTypeLBs from the local cluster where CIS is running. The ServiceTypeLBs can be from the same cluster or from the external clusters. The ServiceTypeLBs from the external clusters can be discovered by setting the serviceTypeLBDiscovery to true in the extendedConfigMap. See [Example](ServiceTypeLB/svc-lb.yaml)

2) MultiCluster ServiceTypeLB - In this case the LB services must be created in all the clusters where CIS is running, and the multiClusterServices annotation must be added to the LB services. The multiClusterServices annotation must contain the clusterNames and Weights. The clusterNames represent the names of the K8S/Openshift clusters where services are created. The Weights represent the weightage for the traffic distribution for the service in a particular cluster. See [Example](ServiceTypeLB/sample-multi-cluster-svc-lb.yaml)

## Known Issues
*  CIS is not able to clear serviceTypeLB status for some external clusters when TS/VS is deleted or label is removed in default mode
* CIS is unable to add the pool-members for external cluster intermittently in default mode when using namespace-labels in the CIS deployment.

## FAQ

### Which services can be provided as multiClusterServices?
Any service running in any OpenShift/Kubernetes clusters which are part of the multiCluster setup can be provided as multiClusterServices.

### Can I specify the services running in CIS HA cluster in multiClusterServices?
Yes. multiClusterServices is applicable to refer the services running in K8S/Openshift clusters which are part of the HA cluster(Primary/Secondary Cluster) as well.

### Is cluster-level traffic splitting supported in default mode?
No, cluster-level traffic splitting is not supported in default mode.

### Can I put the services of a cluster in the maintenance mode?
Yes, you can put the services of a cluster in the maintenance mode, to do so you can update the weights of the services to 0 for that cluster.

### adminState is supported in default mode for a cluster?
No, adminState is not supported in default mode for a cluster and adminState field will be ignored in extendedConfigMap.

### Is ratio or localClusterRatio properties are supported in default mode for extendedConfigMap?
No, ratio or localClusterRatio properties are not supported in default mode for extendedConfigMap.

### Is serviceTypeLBDiscovery supported for modes other than default mode?
No, serviceTypeLBDiscovery is supported only for default mode.

### Are serviceTypeLBDiscovery enabled for all the clusters?
No, serviceTypeLBDiscovery is not enabled for all the clusters. It is enabled only for the cluster where active CIS is running. 

### How to enable the ServiceTypeLBDiscovery for external clusters?
To enable the ServiceTypeLBDiscovery for external clusters, set the serviceTypeLBDiscovery to true in the extendedConfigMap for the respective cluster.

### How to enable the ServiceTypeLBDiscovery for secondary cluster?
To enable the ServiceTypeLBDiscovery for secondary clusters, set the serviceTypeLBDiscovery to true in the extendedConfigMap for the respective cluster.

### Do I need to enable the ServiceTypeLBDiscovery if I am using only multiCluster ServicetypeLB?
No, you don't need to enable the ServiceTypeLBDiscovery if you are using only multiCluster ServiceTypeLB.

### When to enable the ServiceTypeLBDiscovery for a cluster?
Enable the ServiceTypeLBDiscovery for a cluster when you want to expose the ServiceTypeLBs from that cluster to the CIS.

### Does CIS merge the serviceTypeLBs from all the clusters?
No, CIS does not merge the serviceTypeLBs from all the clusters. CIS discovers the serviceTypeLBs from the local cluster where CIS is running and from the external/secondary clusters where serviceTypeLBDiscovery is enabled.

### How to convert Non-MultiCluster ServiceTypeLB to MultiCluster ServiceTypeLB
In order to convert Non-MultiCluster ServiceTypeLB to MultiCluster ServiceTypeLB follow the steps mentioned below:

1) Add the multiClusterServices annotations to the LB services.

   In multiClusterServices annotations you need to provide the clusterNames and Weights.

   clusterNames represent names of the K8S/Openshift clusters where this ServiceTypeLBs are created.

   Weights represent weightage for the traffic distribution for the serviceTypeLB in a particular cluster.

        Example:
        
        cis.f5.com/multiClusterServices: |
        [
        {"clusterName": "cluster2", "weight": 50},
        {"clusterName": "cluster3", "weight": 30},
        {"clusterName": "cluster4", "weight": 20}
        ]
2) Make sure to add these annotations to all the LB services which you want to convert to multiCluster ServiceTypeLB.

3) Make sure to create the multiCluster ServiceTypeLB in each of the clusters where CIS runs.

   These multiCluster ServiceTypeLBs may or may not expose any application in these clusters, however these are required. CIS will read these multiCluster LB Services from the local cluster and discover the associated LB services referenced in the multiClusterServices annotation.

4) All the multiCluster services with the same IP and Port must have the same Specs.

5) The ServiceTypeLBDiscovery can be disabled or removed if you don't want to use non-multiCluster ServiceTypeLB.


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


### Are policy CR supported in default mode?
Yes, Policy CR is supported in all modes same as non-multi-cluster mode.
