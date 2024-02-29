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

| PARAMETER                        | TYPE                          | REQUIRED  | DEFAULT | DESCRIPTION                                                                                                                                                                                                      |
|----------------------------------|-------------------------------|-----------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| host                             | String                        | Optional  | NA      | Virtual Host                                                                                                                                                                                                     |
| defaultPool                      | defaultPool                   | Optional  | NA      | Default BIG-IP Pool for virtual server                                                                                                                                                                           |
| pools                            | List of pool                  | Required  | NA      | List of BIG-IP Pool members                                                                                                                                                                                      |
| virtualServerAddress             | String                        | Optional  | NA      | IP4/IP6 Address of BIG-IP Virtual Server. IP address can also be replaced by a reference to a Service_Address.                                                                                                   |
| serviceAddress                   | List of service address       | Optional  | NA      | Service address definition allows you to add a number of properties to your (virtual) server address                                                                                                             |
| ipamLabel                        | String                        | Optional  | NA      | IPAM label name for IP address management which is map to ip-range in IPAM controller deployment.                                                                                                                |
| virtualServerName                | String                        | Optional  | NA      | Custom name of BIG-IP Virtual Server                                                                                                                                                                             |
| virtualHTTPPort                  | Integer                       | Optional  | NA      | Specify HTTP port for the Virutal Server                                                                                                                                                                         |
| virtualHTTPSPort                 | Integer                       | Optional  | NA      | Specify HTTPS port for the Virtual Server                                                                                                                                                                        |
| tlsProfileName                   | String                        | Optional  | NA      | Describes the TLS profile Name for BIG-IP Virtual Server                                                                                                                                                         |
| rewriteAppRoot                   | String                        | Optional  | NA      | Rewrites the path in the HTTP Header (and Redirects) from \"/" (root path) to specifed path                                                                                                                      |
| waf                              | String                        | Optional  | NA      | Reference to WAF policy on BIG-IP                                                                                                                                                                                |
| snat                             | String                        | Optional  | auto    | Reference to SNAT pool on BIG-IP. The supported values are ``none``, ``auto``, ``self`` and the BIG-IP SNATPool path.                                                                                                                            |
| connectionMirroring              | String                        | Optional  | NA      | Controls connection-mirroring for high-availability.allowed value is "none" or "L4"                                                                                                                              |
| httpTraffic                      | String                        | Optional  | allow   | Configure behavior of HTTP Virtual Server. The allowed values are: allow: allow HTTP (default), none: only HTTPs, redirect: redirect HTTP to HTTPS.                                                              |
| allowVlans                       | List of Vlans                 | Optional  | NA      | list of Vlan objects to allow traffic from                                                                                                                                                                       |  
| hostGroup                        | String                        | Optional  | NA      | Label to group virtualservers with different host names into one in BIG-IP.                                                                                                                                      |
| hostGroupVirtualServerName       | String                        | Optional  | NA      | Custom name of BIG-IP Virtual Server when hostGroup exists.                                                                                                                                     |
| persistenceProfile               | String                        | Optional  | cookie  | CIS uses the AS3 default persistence profile. VirtualServer CRD resource takes precedence over Policy CRD. Allowed values are existing BIG-IP Persistence profiles.                                              |
| htmlProfile                      | String                        | Optional  | NA      | Pathname of existing BIG-IP HTML profile. VirtualServer CRD resource takes precedence over Policy CRD. Allowed values are existing BIG-IP HTML profiles.                                                         |
| dos                              | String                        | Optional  | NA      | Pathname of existing BIG-IP DoS policy.                                                                                                                                                                          |
| botDefense                       | String                        | Optional  | NA      | Pathname of existing BIG-IP botDefense policy.                                                                                                                                                                   |
| profileMultiplex                 | String                        | Optional  | NA      | CIS uses the AS3 default profileMultiplex profile. Allowed values are existing BIG-IP profileMultiplex profiles.                                                                                                 |
| profiles                         | Object                        | Optional  | NA      | BIG-IP TCP Profiles.                                                                                                                                                                                             |
| tcp                              | Object                        | Optional  | NA      | BIG-IP TCP client and server profiles.                                                                                                                                                                           |
| policyName                       | String                        | Optional  | NA      | Name of Policy CRD to attach profiles/policies defined in it.                                                                                                                                                    |
| iRules                           | Array of strings              | Optional  | NA      | iRules to be attached to the VirtualServer.                                                                                                                                                                      |
| allowSourceRange                 | String                        | Optional  | NA      | Comma-separated list of CIDR addresses to allow inbound to services corresponding to VirtualServer CRD. Allowed values are comma-separated, CIDR formatted, IP addresses. For example: ``1.2.3.4/32,2.2.2.0/24`` |
| httpMrfRoutingEnabled            | boolean                       | 	Optional | false   | Specifies whether to use the HTTP message routing framework (MRF) functionality. This property is available on BIGIP 14.1 and above.                                                                             |
| additionalVirtualServerAddresses | List of virtualserver address | Optional  | NA      | List of virtual addresses additional to virtualServerAddress where virtual will be listening on.Uses AS3 virtualAddresses param to expose Virtual server which will listen to each IP address in list            |
| partition                        | String                        | Optional  | NA      | bigip partition                                                                                                                                                                                                  |
| hostPersistence                  | Object                        | Optional  | NA      | Persist session rule action will be added to the VS Policy based on the host. Allowed values are existing BIG-IP Persist session               |

**Note**:
   * **hostGroupVirtualServerName** is valid for Virtual Servers configured with hostGroup. hostGroupVirtualServerName is same in all Virtual Servers definitions in a hostGroup. To update existing hostGrouped Virtual servers with hostGroupVirtualServerName, delete the existing Virtual Servers with that hostGroup and apply after adding hostGroupVirtualServerName to the Virtual Server.


**Default Pool Components**

| PARAMETER           | TYPE              | REQUIRED | DEFAULT     | DESCRIPTION                                                                                                                             |
|---------------------|-------------------|----------|-------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| service             | String            | Required | NA          | Service deployed in kubernetes cluster                                                                                                  |
| serviceNamespace    | String            | Optional | NA          | Namespace of service, define it if service is present in a namespace other than the one where Virtual Server Custom Resource is present |
| servicePort         | Integer or String | Required | NA          | Port to access Service.Could be service port, service port name or targetPort of the service                                            |                                                                                |
| loadBalancingMethod | String            | Optional | round-robin | Allowed values are existing BIG-IP Load Balancing methods for pools.                                                                    |
| nodeMemberLabel     | String            | Optional | NA          | List of Nodes to consider in NodePort Mode as BIG-IP pool members. This Option is only applicable for NodePort Mode                     |
| monitors            | monitor           | Optional | NA          | Specifies multiple monitors for VS Pool                                                                                                 |
| serviceDownAction   | String            | Optional | none        | Specifies connection handling when member is non-responsive                                                                             |
| reselectTries       | Integer           | Optional | 0           | Maximum number of attempts to find a responsive member for a connection                                                                 |
| reference           | String            | Required | NA          | Allowed values are **bigip** or **service**                                                                                             |
| name                | String            | Optional | NA          | pool name or reference to the pool name existing on bigip                                                                               |

**Pool Components**

| PARAMETER           | TYPE                                | REQUIRED | DEFAULT     | DESCRIPTION                                                                                                                             |
|---------------------|-------------------------------------|----------|-------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| name                | String                              | Optional | NA          | pool name                                                                                                                               |
| path                | String                              | Required | NA          | Path to access the service                                                                                                              |
| service             | String                              | Required | NA          | Service deployed in kubernetes cluster                                                                                                  |
| waf                 | String                              | Optional | NA          | Reference to WAF policy on BIG-IP                                                                                                       |
| loadBalancingMethod | String                              | Optional | round-robin | Allowed values are existing BIG-IP Load Balancing methods for pools.                                                                    |
| nodeMemberLabel     | String                              | Optional | NA          | List of Nodes to consider in NodePort Mode as BIG-IP pool members. This Option is only applicable for NodePort Mode                     |
| servicePort         | Integer or String                   | Required | NA          | Port to access Service.Could be service port, service port name or targetPort of the service                                            |                                                                                |
| monitor             | monitor                             | Optional | NA          | Health Monitor to check the health of Pool Members                                                                                      |
| monitors            | monitor                             | Optional | NA          | Specifies multiple monitors for VS Pool                                                                                                 |
| minimumMonitors     | Integer or String | Optional | 1          | Member is down when fewer than minimum monitors report it healthy. Specify ‘all’ to require all monitors to be up.                          |
| rewrite             | String                              | Optional | NA          | Rewrites the path in the HTTP Header while submitting the request to pool members                                                       |
| serviceNamespace    | String                              | Optional | NA          | Namespace of service, define it if service is present in a namespace other than the one where Virtual Server Custom Resource is present |
 | serviceDownAction   | String                              | Optional | none        | Specifies connection handling when member is non-responsive                                                                             |
| reselectTries       | Integer                             | Optional | 0           | Maximum number of attempts to find a responsive member for a connection                                                                 |
| hostRewrite         | String                              | Optional | NA          | Rewrites the hostname http header while submitting the request to pool members                                                          |
| weight              | Integer                             | Optional | NA          | weight allocated to service A in AB deployment                                                                                          |
| alternateBackends   | List of backends for A/B deployment | Optional | NA          | List of alternate backends for AB deployment                                                                                            |

**Note**: **monitors** take priority over **monitor** if both are provided in VS spec.

**alternateBackends Components**

| PARAMETER        | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                                                                   |
|------------------|---------|----------|---------|-----------------------------------------------------------------------------------------------|
| service          | String  | Required | NA      | service name for alternate backend                                                            |
| serviceNamespace | String  | Optional | NA      | namespace of the backend service if its present in namespace different than virtual server CR |
| weight           | Integer | Optional | 100     | weight allocated for the alternate backend service                                            |

**Service_Address Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION                                                                                                            |
| ------ | ------ | ------ | ------ |------------------------------------------------------------------------------------------------------------------------|
| arpEnabled | Boolean | Optional | true | If true (default), the system services ARP requests on this address                                                    |
| icmpEcho | String | Optional | “enable” | If enabled, the system answers ICMP echo requests on this address. Values: “enable”, “disable”, “selective”            |
| routeAdvertisement | String | Optional | “disable” | If enabled, the route is advertised. Values: “enable”, “disable”, “selective”, “always”, “any”, “all”                  |
| spanningEnabled | Boolean | Optional | false | If true, this enables all BIG-IP systems in device group to listen for and process traffic on the same virtual address |
| trafficGroup | String | Optional | "default" | Specifies the traffic group which the Service_Address belongs.                                                         |

**Health Monitor**

| PARAMETER  | TYPE   | REQUIRED | DEFAULT   | DESCRIPTION                                                                                                                         |
|------------|--------|----------|-----------|-------------------------------------------------------------------------------------------------------------------------------------|
| type       | String | Required | NA        | http, https or tcp                                                                                                                  |
| send       | String | Required | “GET /rn” | HTTP request string to send.                                                                                                        |
| recv       | String | Optional | NA        | String or RegEx pattern to match in first 5,120 bytes of backend response.                                                          |
| interval   | Int    | Required | 5         | Seconds between health queries                                                                                                      |
| timeout    | Int    | Optional | 16        | Seconds before query fails                                                                                                          |
| targetPort | Int    | Optional | 0         | port (if any) monitor should probe ,if 0 (default) then pool member port is used.Translates to "Alias Service Port" on BIG-IP pool. |
| name       | String | Required | NA        | Reference to health monitor name existing on bigip                                                                                  |
| reference  | String | Required | NA        | Value should be bigip for referencing custom monitor on bigip                                                                       |
| sslProfile | String | Optional | NA        | sslProfile to attach to custom https monitor created on BIGIP.Applicable only for type "https" monitor                              |

**TCP Profile Components**

| PARAMETER   | TYPE    | REQUIRED | DEFAULT     | DESCRIPTION                                                                                   |
|-------------|---------|----------|-------------|-----------------------------------------------------------------------------------------------|
| client      | String  | Required | Custom_TCP  | CIS uses the AS3 default TCP client profile. Allowed values are existing BIG-IP TCP Client profiles.|
| server      | String  | Optional | NA          | Allowed values are existing BIG-IP TCP Server profiles. **Note: Server TCP Profile can only be used along with Client profile.**|

**Note**:
* monitor can be a reference to existing helathmonitor on bigip in which case, name and reference are required parameters.
* For creating health monitor object on bigip with UserInput type, send, interval are required parameters.

**hostPersistence Components**
| PARAMETER        | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                                                                   |
|------------------|---------|----------|---------|-----------------------------------------------------------------------------------------------|
| method             | String  | Optional | NA      | Allowed values are existing BIG-IP Persist session values.                                  |
| metaData           | Object  | Optional | NA      | Attributes to be configured based on the hostPersistence Method.                            |

**hostPersistence metaData Params**
| PARAMETER        | TYPE    | REQUIRED FOR PERSIST METHODS | DEFAULT | DESCRIPTION                                                                                   |
|------------------|---------|----------------------|---------|-----------------------------------------------------------------------------------------------|
| name             | String  | cookieInsert, cookieRewrite, cookiePassive, cookieHash | NA      | Name of cookie                                                            |
| key              | String  | universal, hash, carp | NA      | The key to use.          |
| netmask          | String  | sourceAddress, destinationAddress | NA      | Network mask                              |
| timeout          | Integer | sourceAddress, destinationAddress, universal, carp, hash, cookieHash | NA      | Timeout value in seconds                              |
| expiry           | String  | cookieInsert, cookieRewrite | NA      | Expiration duration expressed as [Nd][HH:MM[:SS]]                              |
| offset           | Integer | cookieHash | NA      | Offset into hash                              |
| length           | Integer | cookieHash | NA      | Substring length                              |


**Note**
  * hostPersistence will be configured when host is present in the Virtual Server CR.
  * method value none will disable the persistence for the respective host.
  * MetaData params should be configured as per the Method name.


### Examples

   https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer
   
## TLSProfile
   * TLSProfile is used to specify the TLS termination for a single/list of services in a VirtualServer Custom Resource. TLS termination relies on SNI. Any non-SNI traffic received on port 443 may result in connection issues. 
   * TLSProfile can be created either with certificates stored as k8s secrets or can be referenced to profiles existing in BIG-IP
   * Schema Validation
     - OpenAPI Schema Validation
     
        https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml


**TLSProfile Components**

| PARAMETER       | TYPE           | REQUIRED | DEFAULT | DESCRIPTION                                                                                                                                                   |
|-----------------|----------------|----------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| termination     | String         | Required | NA      | Termination on BIG-IP Virtual Server. Allowed options are [edge, reencrypt, passthrough]                                                                      |
| clientSSL       | String         | Required | NA      | Single ClientSSL Profile on the BIG-IP OR a kubernetes secret.                                                                                                |
| clientSSLs      | List of string | Required | NA      | Multiple ClientSSL Profiles on the BIG-IP OR list of kubernetes secrets.                                                                                      |
| serverSSL       | String         | Optional | NA      | Single ServerSSL Profile on the BIG-IP OR a kubernetes secret.                                                                                                |
| serverSSLs      | List of string | Optional | NA      | Multiple ServerSSL Profiles on the BIG-IP OR list of kubernetes secrets.                                                                                      |
| reference       | String         | Required | NA      | Describes the location of profile, BIG-IP,k8s Secrets or mix of serverssl from bigip refernce and clientssl from secret.Allowed values: [bigip,secret,hybrid] |
| clientSSLParams | Object         | Optional | NA      | List of settings that needs to be applied to clientSSL custom profiles created by CIS through reference secret                                                |
| serverSSLParams | Object         | Optional | NA      | List of settings that needs to be applied to serverSSL custom profiles created by CIS through reference secret                                                |

**Note**:
* If reference in tls spec is set to hybrid, profileReference in clientSSLParams and serverSSLParams are used to define profile reference for clientSSL and serverSSL respectively.

**ClientSSLParams**

| PARAMETER            | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                                                                                                                  |
|----------------------|---------|----------|---------|----------------------------------------------------------------------------------------------------------------------------------------------|
| renegotiationEnabled | Boolean | Optional | true    | If false, disables renegotiation on the custom clientssl profile created by CIS through reference secret.                                    |
| profileReference     | String  | Optional | NA      | Allowed values: [bigip, secret]. If reference in tls spec is set to hybrid, this parameter is used to define profile reference for clientSSL |

**ServerSSLParams**

| PARAMETER            | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                                                                                                                  |
|----------------------|---------|----------|---------|----------------------------------------------------------------------------------------------------------------------------------------------|
| renegotiationEnabled | Boolean | Optional | true    | If false, disables renegotiation on the custom serverssl profile created by CIS through reference secret.                                    |
| profileReference     | String  | Optional | NA      | Allowed values: [bigip, secret]. If reference in tls spec is set to hybrid, this parameter is used to define profile reference for serverSSL |

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
| snat                 | String                  | Optional | auto                         |  The supported values are ``none``, ``auto``, ``self`` and the BIGIP SNATPool path.                                                                                                                                            |
| connectionMirroring  | String                  | Optional | NA                           | Controls connection-mirroring for high-availability.allowed value is "none" or "L4"                                                                                                                                                          |
| allowVlans           | List of Vlans           | Optional | Allow traffic from all VLANS | list of Vlan objects to allow traffic from                                                                                                                                                                                                   |
| host                 | String                  | Optional | NA                           | HostName of the Virtual Server                                                                                                                                                                                                               |
| iRules               | List of iRules Optional | Optional | NA                           | List of iRules to attach. Example:["/Common/my-irule"]                                                                                                                                                                                       |
| persistenceProfile   | String                  | Optional | source-address               | CIS uses the AS3 default persistence profile. TransportServer CRD resource takes precedence over Policy CRD. Allowed values are existing BIG-IP Persistence profiles.                                                                        |
| dos                  | String                  | Optional | NA                           | Pathname of existing BIG-IP DoS policy.                                                                                                                                                                                                      |
| profiles             | Object                  | Optional | NA                           | BIG-IP TCP Profiles.                                                                                                                                                                                                                         |
| tcp                  | Object                  | Optional | NA                           | BIG-IP TCP client and server profiles.                                                                                                                                                                                                       |
| profileL4            | String                  | Optional | basic                        | The default value is ``basic`` but it is not configurable if the profileL4 spec is not included in TS or Policy CR. Transport CRD resource takes precedence over Policy CRD resource. Allowed values are existing BIG-IP profileL4 profiles. |
| partition            | String                  | Optional | NA                           | bigip partition                                                                                                                                                                                                                              |

**Pool Components**

| PARAMETER | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                        |
| ------ |---------| ------ | ------ |----------------------------------------------------|
| service | String  | Required | NA | Service deployed in kubernetes cluster             |
| servicePort | Integer or String  | Required | NA | Port to access Service.Could be service port, service port name or targetPort of the service|
| monitor | monitor  | Optional | NA | Health Monitor to check the health of Pool Members |
| monitors | monitor | Optional | NA | Specifies multiple monitors for TS Pool            |
| loadBalancingMethod  | String  | Optional | round-robin      | Allowed values are existing BIG-IP Load Balancing methods for pools.|
| nodeMemberLabel  | String  | Optional | NA      | List of Nodes to consider in NodePort Mode as BIG-IP pool members. This Option is only applicable for NodePort Mode                     |
| serviceDownAction | String  | Optional | none    | Specifies connection handling when member is non-responsive                                                                             |
| reselectTries | Integer | Optional | 0       | Maximum number of attempts to find a responsive member for a connection                                                                 |
| serviceNamespace | String  | Optional | NA      | Namespace of service, define it if service is present in a namespace other than the one where transport Server Custom Resource is present |

**Note**: **monitors** take priority over **monitor** if both are provided in TS spec.

**Service_Address Components**

| PARAMETER | TYPE | REQUIRED | DEFAULT | DESCRIPTION |
| ------ | ------ | ------ | ------ | ------ |
| arpEnabled | Boolean | Optional | true |  If true (default), the system services ARP requests on this address |
| icmpEcho | String | Optional | “enable” | If true (default), the system answers ICMP echo requests on this address. Values: “enable”, “disable”, “selective” |
| routeAdvertisement | String | Optional | “disable” | If true, the route is advertised. Values: “enable”, “disable”, “selective”, “always”, “any”, “all” |
| spanningEnabled | Boolean | Optional | false | Enable all BIG-IP systems in device group to listen for and process traffic on the same virtual address |
| trafficGroup | String | Optional | "default" | Specifies the traffic group which the Service_Address belongs. |

**TCP Profile Components**

| PARAMETER   | TYPE    | REQUIRED | DEFAULT     | DESCRIPTION                                                                                   |
|-------------|---------|----------|-------------|-----------------------------------------------------------------------------------------------|
| client      | String  | Required | Custom_TCP  | CIS uses the AS3 default TCP client profile. Allowed values are existing BIG-IP TCP Client profiles.|
| server      | String  | Optional | NA          | Allowed values are existing BIG-IP TCP Server profiles. **Note: Server TCP Profile can only be used along with Client profile.**|


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

| PARAMETER | TYPE | REQUIRED | DEFAULT     | DESCRIPTION                           |
| ------ | ------ |----------|-------------|---------------------------------------|
| domainName | String | Required | NA          | Domain name of virtual server CRD     |
| dnsRecordType | String | Required | A           | DNS record type                       |
| clientSubnetPreferred | boolean | Optional | false       | Client Subnet Preferred flag          |
| loadBalancerMethod | String | Required | round-robin | Load balancing method for DNS traffic |
| pools | pool | Optional | NA          | GTM Pools                             |

**Pool Components**

| PARAMETER         | TYPE    | REQUIRED | DEFAULT       | DESCRIPTION                                                                                                |
|-------------------|---------|----------|---------------|------------------------------------------------------------------------------------------------------------|
| name              | String  | Required | NA            | Name of the GSLB pool                                                                                      |
| dnsRecordType     | String  | Optional | NA            | DNS record type                                                                                            |
| order             | Integer | Optional | NA            | Priority order of wideIP pool members (effective when used with Global Availability load balancing method) |
| loadBalanceMethod | String  | Optional | round-robin   | Load balancing method for DNS traffic                                                                      |
| lbModeFallback    | String  | Optional | return-to-dns | Load balancing mode that the system uses if preferred and alternate loadbalancing modes are unsuccessful   |
| dataServerName    | String  | Required | NA            | Name of the GSLB server on BIG-IP (i.e. /Common/SiteName)                                                  |
| monitor           | Monitor | Optional | NA            | Monitor for GSLB Pool                                                                                      |
| monitors          | Monitor | Optional | NA            | Specifies multiple monitors for GSLB Pool                                                                  |
| ratio             | Integer | Optional | 1             | Ratio weight assigned to GSLB pool                                                                         |



**Note**: The user needs to mention the same GSLB DataServer Name to dataServerName field, which is created on the BIG-IP common partition.

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

