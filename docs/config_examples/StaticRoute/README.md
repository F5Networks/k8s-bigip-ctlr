# StaticRouteSupport

Support for CIS to configure static routes in BIG-IP with node subnets assigned for the nodes in the OpenShift/k8s cluster.This enables direct routing from BIGIP to k8s Pods in cluster mode without vxaln tunnel configuration on BIGIP.

## Configuration
* To enable the static route configuration, set ``--static-routing-mode`` to ``true`` and ``--orchestration-cni`` to CNI configured in the cluster.
```
   args:
     --static-routing-mode=true
     --orchestration-cni=<ovn-k8s/flannel/antrea/cilium-k8s>
```

## Parameters for StaticRoutingMode

| Parameter            | Type    | Required | Default | Description                                                                                                                        | Allowed Values                      | Agent | Minimum Supported CIS Version |
|----------------------|---------|----------|---------|------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------|-------|-------------------------------|
| static-routing-mode  | Boolean | Optional | false   | Adds Static Routes on the BIGIP so that traffic can be directly route to the pods. (Without tunnels)                               | true, false                         | AS3   | 2.13.0                        |
| orchestration-cni    | String  | Optional | flannel | Kubernetes Cluster CNI Name                                                                                                        | cilium-k8s, flannel,ovn-k8s, antrea | AS3   | 2.13.0                        |
| shared-static-routes | Boolean | Optional | false   | When set to true, static routes are created on the /Common partition, which can be valid only when static-routing-mode is enabled. | true, false                         | AS3   | 2.14.0                        |


## cis-deployment-ovn-k8s.yaml

By deploying this yaml file in your cluster, cis will be configured with static route enabled for ovn-k8s environment.Route will be configured with name in the format ``k8s-<nodename>-<nodeip>`` as shown below.

### BIGIP-Config:

Validate static routes added on to BIGIP
![static_route config](static-route.png?raw=true "static route config")

**Note:**

* StaticRoutingMode is required only with cluster mode where vxlan tunnel is not configured.
* CIS uses --orchestration-cni to read node subnet info and nodeip based on the CNI configured.

### Troubleshooting

In case static routes are not added, along with looking at CIS logs you can also look at below annotations to check if CNI is properly assigning podcidr and nodeip to the node.

**Steps:**

* kubectl describe node ``<nodename>``
* Look for below annotations based on CNI configured, because CIS uses these annotations to read podCIDR and nodeIP allocated to node to create route records dynamically on the BIGIP.

| CNI configured          | Annotations/Spec Required                                                                                                                                                            | Description                                                                                                                                                                                                    |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ovn-k8s                 | OVNK8sNodeSubnetAnnotation = "k8s.ovn.org/node-subnets",OVNK8sNodeIPAnnotation = "k8s.ovn.org/node-primary-ifaddr"                                                                   | k8s.ovn.org/node-subnets is podCIDR allocated to the node.node-primary-ifaddr should have nodeip reachable from BIGIP                                                                                          |
| cilium-k8s              | CiliumK8sNodeSubnetAnnotation12 = "io.cilium.network.ipv4-pod-cidr" or CiliumK8sNodeSubnetAnnotation13 = "network.cilium.io/ipv4-pod-cidr", node ip from field node.Status.Addresses | io.cilium.network.ipv4-pod-cidr or network.cilium.io/ipv4-pod-cidr annotation is used based on cilium version to read podcidr allocated. Nodeip is parsed from node manifest using field node.Status.Addresses | 
| antrea/flannel(default) | podcidr from node.Spec.PodCIDR, nodeIP from node.Status.Addresses                                                                                                                    | podcidr is parsed from node manifest using field node.Spec.PodCIDR and Nodeip is parsed using field node.Status.Addresses                                                                                      |






