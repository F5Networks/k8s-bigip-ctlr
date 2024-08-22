# Service Type LoadBalancer

## Overview:

A service of type LoadBalancer is the simplest and the fastest way to expose a service inside a Kubernetes cluster to the external world. You only need to specify the service type as type=LoadBalancer in the service definition.
Services of type LoadBalancer are natively supported in Kubernetes deployments. For services of the type LoadBalancer, the CIS controller deployed inside the Kubernetes cluster reads service type LB and creates the corresponding LTM virtuals on the BIGIP which load balance the incoming traffic to the Kubernetes cluster.

## Configuration:

serviceType LB is supported with NextGen Routes and Custom Resources:
* With NextGen Routes following parameters are required for CIS deployment: 
    * controller-mode=openshift
* With Custom Resources following parameters are required for CIS deployment:
    * custom-resource-mode=true
* If you are using ipam then configure the following parameter as well:
    * ipam=true

Note:
* CRDs are also required with serviceTypeLB.
* Install the F5 CRDs using following Commands:
```shell
export CIS_VERSION=<cis-version>
# For example
# export CIS_VERSION=v2.12.0
# or
# export CIS_VERSION=2.x-master
#
# the latter if using a CIS image with :latest label
#
kubectl create -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/${CIS_VERSION}/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml

```

## Service Type LoadBalancer Annotations:

Annotation supported for service type LoadBalancer:

| Annotation            | REQUIRED  | DESCRIPTION                                                                                               | EXAMPLE  FILE                         |
|-----------------------|-----------|-----------------------------------------------------------------------------------------------------------|---------------------------------------|
| cis.f5.com/ipamLabel  | Mandatory | Specify the ipamLabel if you are using the FIC controller to configure the ip addresses.                  | example-service-type-lb.yaml          |
| cis.f5.com/health     | Optional  | It configures the health monitor for pools in ltm virtual server.                                         | healthMonitor-serviceTypeLB.yaml      |
| cis.f5.com/policyName | Optional  | Name of Policy CR to attach profiles/policies defined in it.                                              | service-type-lb-with-policyname.yaml  |
| cis.f5.com/ip         | Mandatory | Specify the ip address for the ltm virtual server.                                                        | example-service-type-lb-staic-ip.yaml |
| cis.f5.com/host       | Optional  | Specify the hostname for configuring the WideIP pools on the GTM server, It works along with the EDNS CR. | service-type-lb-with-hostname.yaml    |

Note:-

If cis.f5.com/ipamLabel and cis.f5.com/ip both annotations are provided then cis.f5.com/ip will be given priority and LTM virtual will be created using the IP address provided by cis.f5.com/ip.

## FIC Integration:

See also [How F5 IPAM Controller works](https://clouddocs.f5.com/containers/latest/userguide/ipam/)

## Examples Repository

See also [More examples of ServiceType LB](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/serviceTypeLB).