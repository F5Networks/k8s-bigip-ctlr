# Custom Resource Definitions 

This page is created to document the behaviour of CIS in CRD Mode(ALPHA Release). This is an ALPHA release which supports limited features. Check for the Supported Features and TO BE Implemented sections to understand in detail about the features.  

## What are CRDs? 

* Custom resources are extensions of the Kubernetes API. 
* A resource is an endpoint in the Kubernetes API that stores a collection of API objects of a certain kind; for example, the built-in pods resource contains a collection of Pod objects.
* A custom resource is an extension of the Kubernetes API that is not necessarily available in a default Kubernetes installation. It represents a customization of a particular Kubernetes installation. However, many core Kubernetes functions are now built using custom resources, making Kubernetes more modular.
*  Custom resources can appear and disappear in a running cluster through dynamic registration, and cluster admins can update custom resources independently of the cluster itself. Once a custom resource is installed, users can create and access its objects using kubectl, just as they do for built-in resources like Pods.

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
   
## VirtualServer

* VirtualServer resource defines the load balancing configuration. 
```
 apiVersion: "cis.f5.com/v1"
 kind: VirtualServer
 metadata:
   name: coffee-virtual-server
   labels:
     f5cr: "true"
 spec:
   host: coffee.example.com
   virtualServerAddress: "172.16.3.4"
   pools:
   - path: /coffee
     service: svc-2
     servicePort: 80
```

**Note: The above VirtualServer is insecure, Attach a TLSProfile to make it secure**

## TLSProfile

* TLSProfile is used to specify the TLS termination for a single/list of services in a VirtualServer Custom Resource. TLS termination relies on SNI. Any non-SNI traffic received on port 443 may result in connection issues. 
* TLSProfile can be created either with certificates stored as k8s secrets or can be referenced to profiles existing in BIG-IP

```
  apiVersion: cis.f5.com/v1
  kind: TLSProfile
  metadata:
    name: reencrypt-tls
    labels:
      f5cr: "true"
  spec:
    tls:
      termination: reencrypt
      clientSSL: /common/clientssl
      serverSSL: /common/serverssl
      reference: bigip             # --> reference profiles created in BIG-IP by User
    hosts:
    - coffee.example.com
```

**Known Issue: CIS fails to read TLSProfile Intermittently, We are working with Kubernetes to fix this [issue](https://github.com/kubernetes/code-generator/issues/116)**

## VirtualServer with TLSProfile

* VirtualServer with TLSProfile is used to specify the TLS termination. TLS termination relies on SNI. Any non-SNI traffic received on port 443 may result in connection issues. Below example shows how to attach a TLSProfile to a VirtualServer.

```
 apiVersion: cis.f5.com/v1
  kind: VirtualServer
  metadata:
    name: coffee-virtual-server
    labels:
      f5cr: "true"
    namespace: default
  spec:
    host: coffee.example.com
    tlsProfileName: reencrypt-tls.  # --> This will attach reencrypt-tls TLSProfile
    virtualServerAddress: "172.16.3.4"
    pools:
      - path: /coffee
        service: svc
        servicePort: 80
```

* CIS has a 1:1 mapping for a domain(CommonName) and BIG-IP-VirtualServer.
* User can create any number of custom resources for a single domain. For example, User is flexible to create 2 VirtualServers with 
different terminations(for same domain), one with edge and another with re-encrypt. Todo this he needs to create two VirtualServers one with edge TLSProfile and another with re-encrypt TLSProfile.
  - Both the VirutalServers should be created with same virtualServerAddress
* Single or Group of VirtualServers(with same virtualServerAddress) will be created as one common BIG-IP-VirtualServer.
* If user want to update secure virtual (TLS Virtual) server to insecure virtual (non-TLS server) server. User needs to delete the secure virtual server first and create a new virtual server.

## Transport Server

* TransportServer resource expose non-HTTP traffic configuration for a virtual server address in BIG-IP. 
```
 apiVersion: "cis.f5.com/v1"
 kind: TransportServer
 metadata:
   name: transport-server
   labels:
     f5cr: "true"
 spec:
   virtualServerAddress: "172.16.3.9"
   virtualServerPort: 8585
   mode: standard
   snat: auto
   pool:
     service: svc-3
     servicePort: 8181
     monitor:
      type: tcp
      interval: 10
      timeout: 10
```

## ExternalDNS

* ExternalDNS CRD's allows you to control DNS records dynamically via Kubernetes/OSCP resources in a DNS provider-agnostic way. 
```
apiVersion: "cis.f5.com/v1"
kind: ExternalDNS
metadata:
  name: exdns
  labels:
    f5cr: "true"
spec:
  domainName: example.com
  dnsRecordType: A
  loadBalanceMethod: round-robin
  pools:
  - name: example.site1.com
    dnsRecordType: A
    loadBalanceMethod: round-robin
    dataServerName: /Common/GSLBServer
    monitor:
      type: https
      send: "GET /"
      recv: ""
      interval: 10
      timeout: 10
```

Note: 
* To set up external DNS using BIG-IP GTM user needs to first manually configure GSLB → Datacenter and GSLB → Server on BIG-IP common partition.

Known Issues:
* CIS does not update the GSLB pool members when virtual server CRD's virtualServerAddress is updated or virtual server CRD is deleted for a domain.

## How CIS works with CRDs

* CIS registers to the kubernetes client-go using informers to retrieve Virtual Server, TLSProfile, Service, Endpoint and Node creation, updation and deletion events. Resources identified from such events will be pushed to a Resource Queue maintained by CIS.
* Resource Queue holds the resources to be processed.
* Virtual Server is the Primary citizen. Any changes in TLSProfile, Service, Endpoint, Node will process their affected Virtual Servers. For Example, If svc-a is part of foo-VirtualServer and bar-VirtualServer, Any changes in svc-a will put foo-VirtualServer and bar-VirtualServer in resource queue.
* Worker fetches the affected Virtual Servers from Resource Queue to populate a common structure which holds the configuration of all the Virtual Servers such as TLSProfile, Virtual Server IP, Pool Members and L7 LTM policy actions.
* Vxlan Manager prepares the BIG-IP NET configuration as AS3 cannot process FDB and ARP entries.
* LTM Configuration(using AS3) and NET Configuration(using CCCL) will be created in CIS Managed Partition defined by the User.


**Content**

# VirtualServer
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/_static/config_examples/crd/basic/vs-customresourcedefinition.yml


**VirtualServer Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| host | String | Optional | NA |  Virtual Host |
| pools | List of pool | Required | NA | List of BIG-IP Pool members |
| virtualServerAddress | String | Required | NA | IP Address of BIG-IP Virtual Server |
| virtualServerName | String | Optional | NA | Custom name of BIG-IP Virtual Server |
| TLSProfile | String | Optional | NA | Describes the TLS configuration for BIG-IP Virtual Server |
| rewriteAppRoot | String | Optional | NA |  Rewrites the path in the HTTP Header (and Redirects) from \"/" (root path) to specifed path |
| waf | String | Optional | NA | Reference to WAF policy on BIG-IP |
| snat | String | Optional | auto | Reference to SNAT pool on BIG-IP or Other allowed value is: "none" |

**Pool Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| path | String | Required | NA |  Path to access the service |
| service | String | Required | NA | Service deployed in kubernetes cluster |
| nodeMemberLabel | String | Optional | NA | List of Nodes to consider in NodePort Mode as BIG-IP pool members. This Option is only applicable for NodePort Mode |
| servicePort | String | Required | NA | Port to access Service |
| monitor | String | Optional | NA | Health Monitor to check the health of Pool Members |
| rewrite | String | Optional | NA | Rewrites the path in the HTTP Header while submitting the request to Server in the pool |

**Health Monitor**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| type | String | Required | NA |  http or https |
| send | String | Required | “GET /rn” | HTTP request string to send. |
| recv | String | Optional | NA | String or RegEx pattern to match in first 5,120 bytes of backend response. |
| interval | Int | Required | 5 | Seconds between health queries |
| timeout | Int | Optional | 16 | Seconds before query fails |
   
## TLSProfile
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/_static/config_examples/crd/tls/tls-customresourcedefinition.yml


**TLSProfile Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| termination | String | Required | NA |  Termination on BIG-IP Virtual Server. Allowed options are [edge, reencrypt, passthrough] |
| clientSSL | String | Required | NA | ClientSSL Profile on the BIG-IP. Example /Common/clientssl |
| serverSSL | String | Optional | NA | ServerSSL Profile on the BIG-IP. Example /Common/serverssl |
| reference | String | Required | NA | Describes the location of profile, BIG-IP or k8s Secrets. We currently support BIG-IP profiles only |

# TransportServer
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/_static/config_examples/crd/basic/vs-customresourcedefinition.yml


**TransportServer Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| pool | pool | Required | NA | BIG-IP Pool member |
| virtualServerAddress | String | Required | NA | IP Address of BIG-IP Virtual Server |
| virtualServerPort | String | Required | NA | Port Address of BIG-IP Virtual Server |
| virtualServerName | String | Optional | NA | Custom name of BIG-IP Virtual Server |
| mode | String | Required | NA |  "standard" or "performance". A Standard mode transport server processes connections using the full proxy architecture. A Performance mode transport server uses FastL4 packet-by-packet TCP behavior. |
| snat | String | Optional | auto |  |

**Pool Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| service | String | Required | NA | Service deployed in kubernetes cluster |
| servicePort | String | Required | NA | Port to access Service |
| monitor | String | Optional | NA | Health Monitor to check the health of Pool Members |

**Health Monitor**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| type | String | Required | NA |  http or https |
| interval | Int | Required | 5 | Seconds between health queries |
| timeout | Int | Optional | 16 | Seconds before query fails |


# ExternalDNS
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/_static/config_examples/crd/ExternalDNS/%20externaldns-customresourcedefinition.yml


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


Note: The user needs to mention the same GSLB DataServer Name to dataServerName field, which is create on the BIG-IP common partition.

**GSLB Monitor Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| type | String | Required | NA |  http or https |
| send | String | Required | NA | Send string for monitor i.e. "GET /health  HTTP/1.1\r\nHOST: example.com\r\n" |
| recv | String | Optional | NA | Receive string and can be empty |
| interval | Int | Required | 5 | Seconds between health queries |
| timeout | Int | Optional | 16 | Seconds before query fails |

## Prerequisites
Since CIS is using the AS3 declarative API we need the AS3 extension installed on BIG-IP. Follow the link to install AS3 3.18 is required for CIS 2.0.
 
* Install AS3 on BIG-IP - https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/installation.html

## Installation
**Create CIS Controller, BIG-IP Credentials and RBAC Authentication**

* Install F5 CRDs
  - Download the below file and execute the command as shown.
  
    https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/_static/config_examples/crd/Install/customresourcedefinitions.yml
```sh
kubectl create -f customresourcedefinitions.yml [-n kube-system]
```

* Create BIG-IP Credentials
```sh
kubectl create secret generic bigip-login -n kube-system --from-literal=username=admin --from-literal=password=dummy
```
* Create Service Account
```sh
kubectl create serviceaccount bigip-ctlr [-n kube-system]
```
* Create Cluster Role and Cluster Role Binding
  - Download the below file and execute the command as shown.
  
    https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/_static/config_examples/crd/Install/clusterrole.yml
```sh
kubectl create -f clusterrole.yml [-n kube-system]
```

**Supported Controller Modes: NodePort and Cluster**
* [CIS Architecture](https://clouddocs.f5.com/containers/v2/kubernetes/kctlr-modes.html)

* Deploy k8s-bigip-ctlr in nodeport and customresource mode.
  - Download the below file and execute the command as shown.
  
    https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/_static/config_examples/crd/Install/sample-nodeport-k8s-bigip-ctlr-crd-secret.yml
 ```sh
kubectl create -f sample-nodeport-k8s-bigip-ctlr-crd-secret.yml [-n kube-system]
``` 

## Cluster Mode
**Add BIG-IP device to VXLAN**
* [Overview of CIS VXLAN](https://clouddocs.f5.com/containers/v2/kubernetes/flannel-bigip-info.html)
* [Configure VXLAN with CIS](https://clouddocs.f5.com/containers/v2/kubernetes/kctlr-use-bigip-k8s.html)

* Deploy k8s-bigip-ctlr in cluster and customresource mode.
  - Download the below file and execute the command as shown.
 
      https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/_static/config_examples/crd/Install/sample-cluster-k8s-bigip-ctlr-crd-secret.yml
 ```sh
kubectl create -f sample-cluster-k8s-bigip-ctlr-crd-secret.yml [-n kube-system]
```
## Share Nodes

CIS deployment parameter `--share-nodes` can be used to share the pool member nodes among multiple BIG-IP tenants. `--share-nodes=true` will create nodes on `/Common` partition.

## External DNS

CIS deployment parameter `--gtm-bigip-url`, `--gtm-bigip-username`, `--gtm-bigip-password` and `--gtm-credentials-directory` can be used to configure External DNS.


## Examples

   https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/config_examples/crd

## To Be Implemented
* A/B Deployment
* ErrorPage

## Note
* “--custom-resource-mode=true” deploys CIS in Custom Resource Mode.
* CIS does not watch for ingress/routes/configmaps when deployed in CRD Mode.
* CIS does not support combination of CRDs with any of Ingress/Routes and Configmaps.
