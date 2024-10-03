# Custom Resource Definitions 

This page is created to document the behaviour of CIS in CRD Mode.  

## What are CRDs? 

* Custom resources are extensions of the Kubernetes API. 
* A resource is an endpoint in the Kubernetes API that stores a collection of API objects of a certain kind; for example, the built-in pods resource contains a collection of Pod objects.
* A custom resource is an extension of the Kubernetes API that is not necessarily available in a default Kubernetes installation. It represents a customization of a particular Kubernetes installation. However, many core Kubernetes functions are now built using custom resources, making Kubernetes more modular.
*  Custom resources can appear and disappear in a running cluster through dynamic registration, and cluster admins can update custom resources independently of the cluster itself. Once a custom resource is installed, users can create and access its objects using kubectl, just as they do for built-in resources like Pods.

## How CIS works with CRDs

* CIS registers to the kubernetes client-go using informers to retrieve Transport Server, Service, Endpoint and Node creation, updation and deletion events. Resources identified from such events will be pushed to a Resource Queue maintained by CIS.
* Resource Queue holds the resources to be processed.
* Transport Server is the Primary citizen. Any changes in Service, Endpoint, Node will process their affected Transport Servers. For Example, If svc-a is part of foo-TransportServer and bar-TransportServer, Any changes in svc-a will put foo-TransportServer and bar-TransportServer in resource queue.
* Worker fetches the affected Transport Servers from Resource Queue to populate a common structure which holds the configuration of all the Transport Servers such as Virtual Server IP, Pool Members etc.
* LTM Configuration(using AS3)  will be created in CIS Managed Partition defined by the User.


## Label
* CIS will only process custom resources with f5cr Label as true. 
```
   labels:
     f5cr: "true"  
```

## Contents
* CIS supports following Custom Resources at this point of time.
  - TransportServer
  - IngressLink

## TransportServer
   * TransportServer resource expose non-HTTP traffic configuration for a virtual server address in BIG-IP.
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/cis-20.x/config_examples/customResourceDefinitions/customresourcedefinitions.yml


**TransportServer Components**

| PARAMETER            | TYPE                    | REQUIRED | DEFAULT                      | DESCRIPTION                                                                                                                                                                                                                                  |
|----------------------|-------------------------|----------|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| pool                 | pool                    | Required | NA                           | BIG-IP Pool member                                                                                                                                                                                                                           |
| virtualServerAddress | String                  | Optional | NA                           | IPv4/IPv6 IP Address of BIG-IP Virtual Server. IP address can also be replaced by a reference to a Service_Address.                                                                                                                          |
| ipamLabel            | String                  | Optional | NA                           | IPAM label name for IP address management which is map to ip-range in IPAM controller deployment.                                                                                                                                            |
| hostGroup            | String                  | Optional | NA                           | To leverage the IP from VS CR using the same VS HostGroup name and Vice-versa.                                                                                                                                                               |
| policyName           | String                  | Optional | NA                           | Name of Policy CRD to attach profiles/policies defined in it.                                                                                                                                                                                |
| serviceAddress       | List of service address | Optional | NA                           | Service address definition allows you to add a number of properties to your (virtual) server address                                                                                                                                         |
| virtualServerPort    | String                  | Required | NA                           | Port Address of BIG-IP Virtual Server                                                                                                                                                                                                        |
| virtualServerName    | String                  | Optional | NA                           | Custom name of BIG-IP Virtual Server                                                                                                                                                                                                         |
| type                 | String                  | Optional | tcp                          | "tcp", "udp" or "sctp" L4 transport server type                                                                                                                                                                                              |
| mode                 | String                  | Required | NA                           | "standard" or "performance". A Standard mode transport server processes connections using the full proxy architecture. A Performance mode transport server uses FastL4 packet-by-packet TCP behavior.                                        |
| snat                 | String                  | Optional | auto                         |                                                                                                                                                                                                                                              |
| host                 | String                  | Optional | NA                           | HostName of the Virtual Server                                                                                                                                                                                                               |
| partition            | String                  | Optional | NA                           | bigip partition                                                                                                                                                                                                                              |

**Pool Components**

| PARAMETER | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                        |
| ------ |---------| ------ | ------ |----------------------------------------------------|
| service | String  | Required | NA | Service deployed in kubernetes cluster             |
| servicePort | Integer or String  | Required | NA | Port to access Service.Could be service port, service port name or targetPort of the service|
| monitor | monitor  | Optional | NA | Health Monitor to check the health of Pool Members |
| loadBalancingMethod  | String  | Optional | round-robin      | Allowed values are existing BIG-IP Load Balancing methods for pools.|
| nodeMemberLabel  | String  | Optional | NA      | List of Nodes to consider in NodePort Mode as BIG-IP pool members. This Option is only applicable for NodePort Mode                     |
| serviceNamespace | String  | Optional | NA      | Namespace of service, define it if service is present in a namespace other than the one where transport Server Custom Resource is present |



**Health Monitor**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| type | String | Required | NA |  http or https |
| interval | Int | Required | 5 | Seconds between health queries |
| timeout | Int | Optional | 16 | Seconds before query fails |

### Examples

   https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/cis-20.x/config_examples/customResource/TransportServer

## IngressLink

Refer https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/cis-20.x/config_examples/customResource/IngressLink/README.md


# IP address management using the IPAM controller

CIS can manage the virtual server address for VS and TS using the IPAM controller. The IPAM controller is a container provided by F5 for IP address management and it runs in parallel to the F5 ingress controller a pod in the Kubernetes/Openshift cluster. You can use the F5 IPAM controller to automatically allocate IP addresses to Virtual Servers, Transport Servers from a specified IP address range. You can specify this IP range in the IPAM Controller deployment file while deploying the IPAM controller.

Specify the IPAM label `--ipamLabel` as an argument in VS and TS CRD.
Example: `--ipamLabel="Prod"`

[See Documentation](https://clouddocs.f5.com/containers/latest/userguide/ipam/) 

