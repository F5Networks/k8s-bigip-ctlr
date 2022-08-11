# Custom Resource Definitions 

This page is created to document the behaviour of CIS in CRD Mode.  

## What are CRDs? 

* Custom resources are extensions of the Kubernetes API. 
* A resource is an endpoint in the Kubernetes API that stores a collection of API objects of a certain kind; for example, the built-in pods resource contains a collection of Pod objects.
* A custom resource is an extension of the Kubernetes API that is not necessarily available in a default Kubernetes installation. It represents a customization of a particular Kubernetes installation. However, many core Kubernetes functions are now built using custom resources, making Kubernetes more modular.
*  Custom resources can appear and disappear in a running cluster through dynamic registration, and cluster admins can update custom resources independently of the cluster itself. Once a custom resource is installed, users can create and access its objects using kubectl, just as they do for built-in resources like Pods.

## How CIS works with CRDs

* CIS registers to the kubernetes client-go using informers to retrieve Virtual Server, TLSProfile, Service, Endpoint and Node creation, updation and deletion events. Resources identified from such events will be pushed to a Resource Queue maintained by CIS.
* Resource Queue holds the resources to be processed.
* Virtual Server is the Primary citizen. Any changes in TLSProfile, Service, Endpoint, Node will process their affected Virtual Servers. For Example, If svc-a is part of foo-VirtualServer and bar-VirtualServer, Any changes in svc-a will put foo-VirtualServer and bar-VirtualServer in resource queue.
* Worker fetches the affected Virtual Servers from Resource Queue to populate a common structure which holds the configuration of all the Virtual Servers such as TLSProfile, Virtual Server IP, Pool Members and L7 LTM policy actions.
* Vxlan Manager prepares the BIG-IP NET configuration as AS3 cannot process FDB and ARP entries.
* LTM Configuration(using AS3) and NET Configuration(using CCCL) will be created in CIS Managed Partition defined by the User.


## Label
* CIS will only process custom resources with f5cr Label as true. 
```
   labels:
     f5cr: "true"  
```

## Contents
* CIS supports following Custom Resources at this point of time.
  - VirtualServer
  - TLSProfile
  - TransportServer
  - ExternalDNS
  - IngressLink
  - Policy

## VirtualServer
   * VirtualServer resource defines the load balancing configuration.
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml


**VirtualServer Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| host | String | Optional | NA |  Virtual Host |
| pools | List of pool | Required | NA | List of BIG-IP Pool members |
| virtualServerAddress | String | Optional | NA | IP Address of BIG-IP Virtual Server. IP address can also be replaced by a reference to a Service_Address. |
| serviceAddress | List of service address | Optional | NA | Service address definition allows you to add a number of properties to your (virtual) server address |
| ipamLabel | String | Optional | NA | IPAM label name for IP address management which is map to ip-range in IPAM controller deployment.|
| virtualServerName | String | Optional | NA | Custom name of BIG-IP Virtual Server |
| virtualHTTPPort | Integer | Optional | NA | Specify HTTP port for the Virutal Server|
| virtualHTTPSPort | Integer | Optional | NA | Specify HTTPS port for the Virtual Server |
| TLSProfile | String | Optional | NA | Describes the TLS configuration for BIG-IP Virtual Server |
| rewriteAppRoot | String | Optional | NA |  Rewrites the path in the HTTP Header (and Redirects) from \"/" (root path) to specifed path |
| waf | String | Optional | NA | Reference to WAF policy on BIG-IP |
| snat | String | Optional | auto | Reference to SNAT pool on BIG-IP or Other allowed value is: "none" |
| allowVlans | List of Vlans | Optional | NA | list of Vlan objects to allow traffic from |  

**Pool Components**

| PARAMETER        | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                                                                                         |
|------------------|---------| ------ | ------ |---------------------------------------------------------------------------------------------------------------------|
| path             | String  | Required | NA | Path to access the service                                                                                          |
| service          | String  | Required | NA | Service deployed in kubernetes cluster                                                                              |
| nodeMemberLabel  | String  | Optional | NA | List of Nodes to consider in NodePort Mode as BIG-IP pool members. This Option is only applicable for NodePort Mode |
| servicePort      | String  | Required | NA | Port to access Service                                                                                              |
| monitor          | String  | Optional | NA | Health Monitor to check the health of Pool Members                                                                  |
| monitors         | monitor | Optional | NA | Specifies multiple monitors for VS Pool                                                                             |
| rewrite          | String  | Optional | NA | Rewrites the path in the HTTP Header while submitting the request to Server in the pool                             |
| serviceNamespace | String | Optional | NA | Namespace of service, define it if service is present in a namespace other than the one where Virtual Server Custom Resource is present |

**Service_Address Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| arpEnabled | Boolean | Optional | true |  If true (default), the system services ARP requests on this address |
| icmpEcho | String | Optional | “enable” | If true (default), the system answers ICMP echo requests on this address. Values: “enable”, “disable”, “selective” |
| routeAdvertisement | String | Optional | “disable” | If true, the route is advertised. Values: “enable”, “disable”, “selective”, “always”, “any”, “all” |
| spanningEnabled | Boolean | Optional | false | Enable all BIG-IP systems in device group to listen for and process traffic on the same virtual address |
| trafficGroup | String | Optional | "default" | Specifies the traffic group which the Service_Address belongs. |

**Health Monitor**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION                                                                                                                        |
| ------ | ------ | ------ | ------ |------------------------------------------------------------------------------------------------------------------------------------|
| type | String | Required | NA | http, https or tcp                                                                                                                 |
| send | String | Required | “GET /rn” | HTTP request string to send.                                                                                                       |
| recv | String | Optional | NA | String or RegEx pattern to match in first 5,120 bytes of backend response.                                                         |
| interval | Int | Required | 5 | Seconds between health queries                                                                                                     |
| timeout | Int | Optional | 16 | Seconds before query fails                                                                                                         |
| targetPort | Int | Optional | 0 | port (if any) monitor should probe ,if 0 (default) then pool member port is used.Translates to "Alias Service Port" on BIG-IP pool. |
| name | String | Required | NA | Refrence to health monitor name existing on bigip                                                                                  |
| reference | String  | Required | NA | Value should be bigip for referencing custom monitor on bigip                                                                      |

**Note**:
* monitor can be a reference to existing helathmonitor on bigip in which case, name and reference are required parameters.
* For creating health monitor object on bigip with UserInput type, send, interval are required parameters.

### Examples

   https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer
   
## TLSProfile
   * TLSProfile is used to specify the TLS termination for a single/list of services in a VirtualServer Custom Resource. TLS termination relies on SNI. Any non-SNI traffic received on port 443 may result in connection issues. 
   * TLSProfile can be created either with certificates stored as k8s secrets or can be referenced to profiles existing in BIG-IP
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml


**TLSProfile Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| termination | String | Required | NA |  Termination on BIG-IP Virtual Server. Allowed options are [edge, reencrypt, passthrough] |
| clientSSL | String | Required | NA | ClientSSL Profile on the BIG-IP. Example /Common/clientssl |
| serverSSL | String | Optional | NA | ServerSSL Profile on the BIG-IP. Example /Common/serverssl |
| reference | String | Required | NA | Describes the location of profile, BIG-IP or k8s Secrets. We currently support BIG-IP profiles only |

**Note**:
* CIS has a 1:1 mapping for a domain(CommonName) and BIG-IP-VirtualServer.
* User can create any number of custom resources for a single domain. For example, User is flexible to create 2 VirtualServers with 
different terminations(for same domain), one with edge and another with re-encrypt. Todo this he needs to create two VirtualServers one with edge TLSProfile and another with re-encrypt TLSProfile.
  - Both the VirutalServers should be created with same virtualServerAddress
* Single or Group of VirtualServers(with same virtualServerAddress) will be created as one common BIG-IP-VirtualServer.
* If user want to update secure virtual (TLS Virtual) server to insecure virtual (non-TLS server) server. User needs to delete the secure virtual server first and create a new virtual server.

### Examples

   https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServerWithTLSProfile

## TransportServer
   * TransportServer resource expose non-HTTP traffic configuration for a virtual server address in BIG-IP.
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml


**TransportServer Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| pool | pool | Required | NA | BIG-IP Pool member |
| virtualServerAddress | String | Optional | NA | IP Address of BIG-IP Virtual Server. IP address can also be replaced by a reference to a Service_Address. |
| ipamLabel | String | Optional | NA | IPAM label name for IP address management which is map to ip-range in IPAM controller deployment.|
| serviceAddress | List of service address | Optional | NA | Service address definition allows you to add a number of properties to your (virtual) server address |
| virtualServerPort | String | Required | NA | Port Address of BIG-IP Virtual Server |
| virtualServerName | String | Optional | NA | Custom name of BIG-IP Virtual Server |
| type | String | Optional | tcp | "tcp" or "udp" L4 transport server type |
| mode | String | Required | NA |  "standard" or "performance". A Standard mode transport server processes connections using the full proxy architecture. A Performance mode transport server uses FastL4 packet-by-packet TCP behavior. |
| snat | String | Optional | auto |  |
| allowVlans | List of Vlans | Optional | Allow traffic from all VLANS | list of Vlan objects to allow traffic from |

**Pool Components**

| PARAMETER | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                        |
| ------ |---------| ------ | ------ |----------------------------------------------------|
| service | String  | Required | NA | Service deployed in kubernetes cluster             |
| servicePort | String  | Required | NA | Port to access Service                             |
| monitor | String  | Optional | NA | Health Monitor to check the health of Pool Members |
| monitors | monitor | Optional | NA | Specifies multiple monitors for TS Pool            |

**Service_Address Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| arpEnabled | Boolean | Optional | true |  If true (default), the system services ARP requests on this address |
| icmpEcho | String | Optional | “enable” | If true (default), the system answers ICMP echo requests on this address. Values: “enable”, “disable”, “selective” |
| routeAdvertisement | String | Optional | “disable” | If true, the route is advertised. Values: “enable”, “disable”, “selective”, “always”, “any”, “all” |
| spanningEnabled | Boolean | Optional | false | Enable all BIG-IP systems in device group to listen for and process traffic on the same virtual address |
| trafficGroup | String | Optional | "default" | Specifies the traffic group which the Service_Address belongs. |

**Health Monitor**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| type | String | Required | NA |  http or https |
| interval | Int | Required | 5 | Seconds between health queries |
| timeout | Int | Optional | 16 | Seconds before query fails |
| targetPort | Int | Optional | 0 | Port (if any) monitor should probe ,if 0 (default) then pool member port is used.Translates to "Alias Service Port" on BIG-IP pool.  |
| name | String | Required | NA | Refrence to health monitor name existing on bigip|
| reference | String  | Required | NA | Value should be bigip for referencing custom monitor on bigip|

**Note**:
* monitor can be a reference to existing helathmonitor on bigip in which case, name and reference are required parameters.
* For creating health monitor object on bigip with UserInput type, send, interval are required parameters.

### Examples

   https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/TransportServer

## ExternalDNS
   * ExternalDNS CRD's allows you to control DNS records dynamically via Kubernetes/OSCP resources in a DNS provider-agnostic way.
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml


**ExternalDNS Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| domainName | String | Required | NA | Domain name of virtual server CRD |
| dnsRecordType | String | Required | A | DNS record type |
| loadBalancerMethod | String | Required | round-robin | Load balancing method for DNS traffic |
| pools | pool | Optional | NA | GTM Pools |

**Pool Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| name | String | Required | NA | Name of the GSLB pool |
| dnsRecordType | String | Optional | NA | DNS record type |
| loadBalancerMethod | String | Optional | round-robin | Load balancing method for DNS traffic |
| dataServerName | String | Required | NA | Name of the GSLB server on BIG-IP (i.e. /Common/SiteName) |
| monitor | Monitor | Optional | NA | Monitor for GSLB Pool |
| monitors | Monitor | Optional | NA | Specifies multiple monitors for GSLB Pool |


**Note**: The user needs to mention the same GSLB DataServer Name to dataServerName field, which is create on the BIG-IP common partition.

**GSLB Monitor Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| type | String | Required | NA |  http or https |
| send | String | Required | NA | Send string for monitor i.e. "GET /health  HTTP/1.1\r\nHOST: example.com\r\n" |
| recv | String | Optional | NA | Receive string and can be empty |
| interval | Int | Required | 5 | Seconds between health queries |
| timeout | Int | Optional | 16 | Seconds before query fails |

Refer https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/ExternalDNS/README.md 

**Note**: 
* To set up external DNS using BIG-IP GTM user needs to first manually configure GSLB → Datacenter and GSLB → Server on BIG-IP common partition.
* CIS deployment parameter `--gtm-bigip-url`, `--gtm-bigip-username`, `--gtm-bigip-password` and `--gtm-credentials-directory` can be used to configure External DNS. [See Documentation](https://clouddocs.f5.com/containers/latest/userguide/cis-installation.html)

Known Issues:
* CIS does not update the GSLB pool members when virtual server CRD's virtualServerAddress is updated or virtual server CRD is deleted for a domain.

### Examples

   https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/ExternalDNS


## IngressLink

Refer https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/IngressLink/README.md

## Policy CRD 

Refer https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/Policy


# Note
* “--custom-resource-mode=true” deploys CIS in Custom Resource Mode. [See Documentation](https://clouddocs.f5.com/containers/latest/userguide/cis-installation.html)
* CIS does not watch for ingress/routes/configmaps when deployed in CRD Mode.
* CIS does not support combination of CRDs with any of Ingress/Routes and Configmaps.

# IP address management using the IPAM controller

CIS can manage the virtual server address for VS and TS using the IPAM controller. The IPAM controller is a container provided by F5 for IP address management and it runs in parallel to the F5 ingress controller a pod in the Kubernetes/Openshift cluster. You can use the F5 IPAM controller to automatically allocate IP addresses to Virtual Servers, Transport Servers from a specified IP address range. You can specify this IP range in the IPAM Controller deployment file while deploying the IPAM controller.

Specify the IPAM label `--ipamLabel` as an argument in VS and TS CRD.
Example: `--ipamLabel="Prod"`

[See Documentation](https://clouddocs.f5.com/containers/latest/userguide/ipam/) 

