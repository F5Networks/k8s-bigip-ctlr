# StaticRouteSupport

Support for CIS to configure static routes in BIG-IP with node subnets assigned for the nodes in the OpenShift/k8s cluster.This enables direct routing from BIGIP to k8s Pods in cluster mode without vxaln tunnel configuration on BIGIP.

## Configuration
* To enable the static route configuration, set ``--static-routing-mode`` to ``true`` and ``--orchestration-cni`` to CNI configured in the cluster.
```
   args:
     --static-routing-mode=true
     --orchestration-cni=<ovn-k8s/flannel/antrea>
```

## cis-deployment-ovn-k8s.yaml

By deploying this yaml file in your cluster, cis will be configured with static route enabled for ovn-k8s environment.Route will be configured with name in the format ``k8s-<nodename>-<nodeip>`` as shown below.

### BIGIP-Config:

Validate static routes added on to BIGIP
![static_route config](static-route.png?raw=true "static route config")

**Note:**

* StaticRoutingMode is required only with cluster mode where vxlan tunnel is not configured.
* CIS uses --orchestration-cni to read node subnet info and nodeip based on the CNI configured.





