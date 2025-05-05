CIS and IPAM Release Upgrade Process
=======================================================================

This page shows you how to upgrade from one version of CIS, IPAM. Each section shows you steps for upgrading as well as any behavioral changes. 

Refer to the [Release Notes](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst) for additional information.

Latest [RBAC](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/rbac/clusterrole.yaml) and [CR Schema](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml)

Compatibility Matrix
--------------------

| CIS Version | BIG-IP Version | Kubernetes Version | OpenShift Version                                             | SDN | OVN (Cluster Mode) | AS3 Version | FIC Version | FIC Chart Version | CIS Chart Version | OS Version                                          |
|-------------|----------------|--------------------|---------------------------------------------------------------|-----|--------------------|-------------|-------------|-------------------|-------------------|-----------------------------------------------------|
| v1.14.0     | v15.1          | v1.16.2            | v4.2                                                          | Yes | -                  | v3.17       |             |                   | v0.0.7            | Debian GNU/Linux 10.3 (bluster)                     |
| v1.14.1     | v15.1          | v1.16.2            | v4.2                                                          | Yes | -                  | v3.17       |             |                   | v0.0.7            | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v1.14.2     | v15.1          | v1.16.2            | v4.2                                                          | Yes | -                  | v3.17       |             |                   | v0.0.7            | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.0        | v15.1          | v1.18              | v4.3                                                          | Yes | -                  | v3.18       |             |                   | v0.0.7            | Red Hat Enterprise Linux Server release 7.8 (Maipo) |
| v2.1        | v15.1          | v1.18              | v4.4.5                                                        | Yes | -                  | v3.20       |             |                   | v0.0.7            | Red Hat Enterprise Linux Server release 7.8 (Maipo) |
| v2.1.1      | v15.1          | v1.18              | v4.5                                                          | Yes | -                  | v3.21       |             |                   | v0.0.8            | Red Hat Enterprise Linux Server release 7.8 (Maipo) |
| v2.2.0      | v15.1          | v1.18              | v4.5                                                          | Yes | -                  | v3.23       |             |                   | v0.0.9            | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.2.1      | v15.1          | v1.18              | v4.6.4                                                        | Yes | -                  | v3.24       |             |                   | v0.0.10           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.2.2      | v16.0          | v1.19              | v4.6.4                                                        | Yes | -                  | v3.25       |             |                   | v0.0.11           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.3        | v16.0          | v1.19              | v4.6.4                                                        | Yes | -                  | v3.25       |             |                   | v0.0.12           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.4.0      | v16.0          | v1.20              | v4.6.4                                                        | Yes | -                  | v3.25       | v0.1.2      |                   | v0.0.13           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.4.1      | v16.0          | v1.20              | v4.6.4                                                        | Yes | -                  | v3.25       | v0.1.3      |                   | v0.0.14           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.5.0      | v16.0          | v1.21              | v4.7.13                                                       | Yes | -                  | v3.28       | v0.1.4      |                   | v0.0.14           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.6.0      | v16.0          | v1.21              | v4.8.12 (OpenShift SDN and OVN- Kubernetes with HyperOverlay) | Yes | Yes                | v3.28       | v0.1.5      |                   | v0.0.16           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.7.0      | v16.0          | v1.22              | v4.9                                                          | Yes | Yes                | v3.30       | v0.1.6      | v0.0.1            | v0.0.17           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.7.1      | v16.0          | v1.22              | v4.9                                                          | Yes | Yes                | v3.30       | v0.1.6      | v0.0.1            | v0.0.18           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.8.0      | v16.0          | v1.22              | v4.9                                                          | Yes | Yes                | v3.30       | v0.1.6      | v0.0.1            | v0.0.19           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.8.1      | v16.0          | v1.22              | v4.9                                                          | Yes | Yes                | v3.30       | v0.1.7      | v0.0.1            | v0.0.19           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.9.0      | v16.0          | v1.23              | v4.10.3                                                       | Yes | Yes                | v3.36       | v0.1.8      | v0.0.1            | v0.0.20           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.9.1      | v16.0          | v1.23              | v4.10.3                                                       | Yes | Yes                | v3.36       | v0.1.8      | v0.0.2            | v0.0.21           | Red Hat Enterprise Linux Server release 7.9 (Maipo) |
| v2.10.0     | v16.0          | v1.24              | v4.11.1                                                       | Yes | Yes                | v3.38       | v0.1.8      | v0.0.2            | v0.0.22           | Red Hat Enterprise Linux release 8.6 (Ootpa)        |
| v2.10.1     | v16.0          | v1.24              | v4.11.1                                                       | Yes | Yes                | v3.38       | v0.1.8      | v0.0.2            | v0.0.22           | Red Hat Enterprise Linux release 8.6 (Ootpa)        |
| v2.11.0     | v16.0          | v1.24              | v4.11.1                                                       | Yes | Yes                | v3.38       | v0.1.8      | v0.0.3            | v0.0.22           | Red Hat Enterprise Linux release 8.7 (Ootpa)        |
| v2.11.1     | v16.0          | v1.24              | v4.11.1                                                       | Yes | Yes                | v3.41       | v0.1.8      | v0.0.4            | v0.0.23           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.12.0     | v16.0          | v1.24              | v4.11.1                                                       | Yes | Yes                | v3.41       | v0.1.9      | v0.0.4            | v0.0.24           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.12.1     | v16.0          | v1.24              | v4.12.0*                                                      | Yes | Yes                | v3.41       | v0.1.9      | v0.0.4            | v0.0.24           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.13.0     | v16.0          | v1.27              | v4.12.0*                                                      | Yes | Yes                | v3.45       | v0.1.9      | v0.0.4            | v0.0.25           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.13.1     | v16.0          | v1.27              | v4.12.0*                                                      | Yes | Yes                | v3.45       | v0.1.9      | v0.0.4            | v0.0.25           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.14.0     | v17.0          | v1.27              | v4.12.0*                                                      | Yes | Yes                | v3.45       | v0.1.9      | v0.0.4            | v0.0.26           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.15.0     | v17.0          | v1.28              | v4.13.0*                                                      | Yes | Yes                | v3.48       | v0.1.9      | v0.0.4            | v0.0.27           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.15.1     | v17.0          | v1.29              | v4.14.0*                                                      | Yes | Yes                | v3.48       | v0.1.9      | v0.0.4            | v0.0.28           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.16.0     | v17.0          | v1.29              | v4.14.0*                                                      | Yes | Yes                | v3.50       | v0.1.9      | v0.0.4            | v0.0.29           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.16.1     | v17.0          | v1.29              | v4.14.0*                                                      | Yes | Yes                | v3.50       | v0.1.10     | v0.0.4            | v0.0.29           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.17.0     | v17.0          | v1.31              | v4.15.0*                                                      | Yes | Yes                | v3.50       | v0.1.10     | v0.0.5            | v0.0.30           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.17.1     | v17.0          | v1.31              | v4.15.0*                                                      | Yes | Yes                | v3.50       | v0.1.10     | v0.0.5            | v0.0.31           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.18.0     | v17.0          | v1.31              | v4.16.0*                                                      | Yes | Yes                | v3.52       | v0.1.11     | v0.0.5            | v0.0.32           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.18.1     | v17.0          | v1.31              | v4.16.0*                                                      | Yes | Yes                | v3.52       | v0.1.11     | v0.0.5            | v0.0.33           | Red Hat Enterprise Linux release 9.1 (Plow)         |
| v2.19.0     | v17.0          | v1.31              | v4.16.0*                                                      | Yes | Yes                | v3.52       | v0.1.11     | v0.0.5            | v0.0.34           | Red Hat Enterprise Linux release 9.1 (Plow)         |
Note: For OCP version 4.12, CIS is compatible with IPv4 and dual stack IPv4.

Compatibility Matrix for Multi Cluster Support
----------------------------------------------

| CIS Version | BIG-IP Version | Kubernetes Version | OpenShift Version | NodePort | SDN | OVN (Cluster Mode) | AS3 Version | CIS Chart Version | 
|-------------|----------------|--------------------|-------------------|----------|-----|--------------------|-------------|-------------------|
| v2.14.0     | v16.0          | v1.27              | v4.12.0           | Yes      | No  | Yes                | v3.45       | v0.0.26           |
| v2.15.0     | v16.0          | v1.28              | v4.13.0           | Yes      | No  | Yes                | v3.48       | v0.0.27           |
| v2.16.0     | v17.0          | v1.29              | v4.14.0*          | Yes      | No  | Yes                | v3.50       | v0.0.29           |
| v2.17.0     | v17.0          | v1.31              | v4.15.0*          | Yes      | No  | Yes                | v3.50       | v0.0.30           |
| v2.18.0     | v17.0          | v1.31              | v4.16.0*          | Yes      | No  | Yes                | v3.52       | v0.0.32           |
| v2.18.1     | v17.0          | v1.31              | v4.16.0*          | Yes      | No  | Yes                | v3.52       | v0.0.33           |
| v2.19.0     | v17.0          | v1.31              | v4.16.0*          | Yes      | No  | Yes                | v3.52       | v0.0.34           |



CIS Features and Examples
-------------------------

| Feature                              | Example                                                                                                                                                                                             | Description                                                                                                                                             | CIS Version |
|--------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| user-defined-as3                     | [Example](https://clouddocs.f5.com/containers/latest/userguide/config-map.html#modify-as3-configmap)                                                                                                | Allows users to modify AS3 ConfigMap in CIS                                                                                                             | v2.0.0      |
| override-as3                         | [Example](https://clouddocs.f5.com/containers/latest/userguide/config-map.html#override-as3-configmap)                                                                                              | The Override AS3 ConfigMap hosts a part of AS3 as a configuration to be overridden. Using this ConfigMap, CIS implements the AS3 override functionality | v2.0.0      |
| VirtualServer With TLS profile       | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/VirtualServerWithTLSProfile)                                                             | VirtualServer with TLSProfile is used to specify the TLS termination. TLS termination relies on SNI                                                     | v2.1.0      |
| virtualServer insecure               | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/VirtualServer/unsecure-virtual-server)                                                   | Allows user to create a Virtual Server on BIG-IP with VIP. It will load balance the traffic for domain                                                  | v2.1.1      |
| Health Monitors in EDNS              | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResource/ExternalDNS/externaldns-tcp-monitor.yaml)                                      | Configure health monitor for GSLB pools in DNS. Heath monitor is supported for each pool members                                                        | v2.2.0      |
| virtualServer with waf               | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/VirtualServer/waf)                                                                       | By deploying this yaml file in your cluster, CIS will create a Virtual Server containing WAF policy on BIG-IP                                           | v2.2.0      |
| virtualServer Multiport Services     | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/VirtualServer/MultiPortServices)                                                         | Allows to configure multiple port definitions on a Service object                                                                                       | v2.2.0      |
| TransportServer with IPAM Label      | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResource/TransportServer/transport-server-with-ipamLabel/transport-with-ipamLabel.yaml) | ipamLabel definition allows the user manage the virtual server addresss using the F5 IPAM controller                                                    | v2.4.0      |
| TransportServer with Service address | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResource/TransportServer/ts-with-service-address.yaml)                                  | Service address definition allows you to add a number of properties to your (virtual) server address                                                    | v2.4.0      |
| IngressLink with IPAM Label          | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResource/IngressLink/ingressLink-with-ipamLabel/ingresslink-with-ipamLabel.yaml)        | Allows users to create a IngressLink on BIG-IP with virtual server address provided by IPAM controller                                                  | v2.6.0      |
| virtualServer with HostGroup         | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/VirtualServer/virtual-with-hostGroup)                                                    | Allows Associated VirutalServers are grouped based on “hostGroup” parameter. MultiHost support for VS CRD is achieved using this parameter              | v2.7.0      |
| virtualServer with Wildcard domain   | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/VirtualServer/virtual-with-wildcard-domain)                                              | Allows users to create a Virtual Server on BIG-IP with wildcard domain name                                                                             | v2.7.0      |
| Policy-CRD                           | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResource/Policy/sample-policy.yaml)                                                     | Policy CRD resource defines the profile configuration for a virtual server in BIG-IP                                                                    | v2.7.0      |
| Filter-Tenants                       | [Example](https://clouddocs.f5.com/containers/latest/userguide/config-map.html#filter-tenant-support-for-as3-configmap)                                                                             | Uses tenant filtering API for AS3 declaration. This allows CIS to process each AS3 Tenant separately. Compatible with ConfigMap only                    | v2.7.0      |

### **Upgrading from 1.14.to 2.0:**

Refer Release Notes for [CIS v2.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#20)

**_Functionality Changes:_**

* AS3 is the default agent, Requires AS3 versions>= 3.18 for 2.x releases.
* User defined AS3 Config Map in CIS watched namespaces. 
* New RH container registry : [registry.connect.redhat.com/f5networks/cntr-ingress-svcs](http://registry.connect.redhat.com/f5networks/cntr-ingress-svcs) 
* Custom Resource Definition (CRD) -Alpha available with custom resource virtual-server. [CRD Doc and Examples](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResource/CustomResource.md).

### **Upgrading from 2.0 to 2.1:**

Refer Release Notes for [CIS v2.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#21)

**_Functionality Changes:_**

* CIS will not create _AS3 partition anymore. 
* Deprecated --userdefined-as3-declaration CIS deployment option as CIS now supports Multiple AS3 ConfigMaps 
* Those migrating from agent CCCL to agent AS3 :
  * User should clean up LTM resources in BIG-IP partition created by CCCL before migrating to CIS 2.1.
  * Steps to clean up LTM resources in BIG-IP partition using AS3 
  * Use below POST call along with this [AS3 declaration](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/v2.6.1/docs/config_examples/example-empty-AS3-declaration.yaml).
    
    mgmt/shared/appsvcs/declare 
  * Note: Please modify <bigip-ip> in above POST call and <bigip-partition> name in [AS3 declaration](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/v2.6.1/docs/config_examples/example-empty-AS3-declaration.yaml)

### **Upgrading from 2.1 to 2.1.1:**

Refer Release Notes for [CIS v2.1.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#211)

**_Functionality Changes:_**

* Custom Resource Definition(CRD)- Preview version available with virtual server and TLSProfile custom resources. 
* Added support for installation using Helm and Operator.

### **Upgrading from 2.1.1 to 2.2.0:**

Refer Release Notes for [CIS v2.2.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#220)

**_Functionality Changes:_**

* Share Nodes implementation for CRD, Ingress and Routes. 
* IngressLink - Nginx CIS connector.

### **Upgrading from 2.2.0 to 2.2.1:**

Refer Release Notes for [CIS v2.2.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#221)

**_Functionality Changes:_**

* External DNS CRD – Preview available in CRD mode.
* ConfigMap not working for 2.2.1 
* servicePort value in ConfigMap requires the service's nodeport value 
* CRD schema definition for [External DNS](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml) and [examples](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/ExternalDNS).

### **Upgrading from 2.2.1 to 2.2.2:**

Refer Release Notes for [CIS v2.2.2](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#222)

**_Functionality Changes:_**

* CIS handles validation of BIG-IP ClientSSL/ServerSSL. 
* Virtual Server demotes from CMP when updating to CIS v 2.2.2. 
* servicePort value in ConfigMap definition needs to be equal to "service exposed port"

### **Upgrading from 2.2.2 to 2.3.0:**

Refer Release Notes for [CIS v2.3.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#230)

**_Functionality Changes:_**

* CIS supports IP address assignment to Virtual Server CRD using [F5 IPAM Controller](https://github.com/F5Networks/f5-ipam-controller/releases). Refer for [Examples](https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md).
* CIS allows user to leverage Virtual IP address using either [F5 IPAM Controller](https://github.com/F5Networks/f5-ipam-controller/releases) or virtualServerAddress field in VirtualServer CRD 
* iRule reference for VirtualServer CRDs 
* Enabling VLANS for VirtualServer and TransportServer CRDs 
* Updated CR Kind from NginxCisConnector to IngressLink 
* Helm Chart Enhancements:Added Support for [livenessProbe](https://github.com/F5Networks/charts/issues/34), [ReadinessProbe](https://github.com/F5Networks/charts/issues/34), [nodeSelectors](https://github.com/F5Networks/charts/issues/38), [tolerations](https://github.com/F5Networks/charts/issues/38). 
* Workaround for CIS in [IPAM mode](https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md).

### **Upgrading from 2.3.0 to 2.4.0:**

Refer Release Notes for [CIS v2.4.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#240)

**_Functionality Changes:_**

* CIS supports IP address assignment to kubernetes service type LoadBalancer using [F5 IPAM Controller](https://github.com/F5Networks/f5-ipam-controller/releases). Refer for [Examples](https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md). 
* CIS supports IP address assignment to TransportServer Custom Resources using [F5 IPAM Controller](https://github.com/F5Networks/f5-ipam-controller/releases). Refer for [Examples](https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md). 
* Integrated the IngressLink mode with CRD mode. 
* Helm Chart Enhancements:
  * Updated the [Custom Resource Definitions](https://raw.githubusercontent.com/F5Networks/charts/gh-pages/example_values/f5-bigip-ctlr/cis-k8s-custom-resource-values.yaml) for VirtualServer and TransportServer resources. 
  * Updated the [RBAC](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/helm-charts/f5-bigip-ctlr/templates/f5-bigip-ctlr-clusterrole.yaml) to support service type LoadBalancer.

### **Upgrading from 2.4.0 to 2.5.0:**

Refer Release Notes for [CIS v2.5.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#250)

**_Functionality Changes:_**

* Moving to CIS > 2.4.1 requires update to RBAC and CR schema definition before upgrade. See [RBAC](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/rbac/clusterrole.yaml) and [CR schema](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml) 
* Added support for CIS deployment configuration options:
  * --periodic-sync-interval - Configure the periodic sync of Kubernetes resources.
  * --hubmode - Enable Support for ConfigMaps to monitor services in same and different namespaces. 
  * --disable-teems - Configure to send anonymous analytics data to F5.
* CIS 2.5 supports Kubernetes [networking.k8s.io/v1](http://networking.k8s.io/v1) Ingress and IngressClass. With Kubernetes > 1.18, 
  * Reconfigure CIS ClusterRole - we removed resourceName to monitor all secrets. 
  * Create IngressClass before version upgrade.
* To upgrade CIS using operator in OpenShift, 
  * Install IngressClass manually. 
  * Install CRDs manually if using CIS CustomResources (VirtualServer/TransportServer/IngressLink).
* F5 IPAM Controller supports InfoBlox (Preview - Available for VirtualServer CR only. See [documentation](https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md)). 
* OpenShift operator fails to install multiple CIS instances due to already existing CRD's.

### **Upgrading from 2.5.0 to 2.6.0:**

Refer Release Notes for [CIS v2.6.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#260)

**_Functionality Changes:_**

* CIS supports IP address assignment to IngressLink Custom Resources using F5 IPAM Controller(See [documentation](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/IngressLink/ingressLink-with-ipamLabel))
* CIS supports IPV6 address in bigip-url & gtm-bigip-url parameter 
* F5 IPAM Controller supports InfoBlox (See [FIC release notes](https://github.com/F5Networks/f5-ipam-controller/blob/main/docs/RELEASE-NOTES.rst))

### **Upgrading from 2.6.0 to 2.6.1:**

Refer Release Notes for [CIS v2.6.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#261)

**_Functionality Change:_**

* Moving from CIS > 2.6 with IPAM, see troubleshooting guide for IPAM issue _ipams.fic.f5.com_ not found. Refer [Troubleshooting Section](https://github.com/F5Networks/f5-ipam-controller/blob/main/docs/faq/README.md)

### **Upgrading from 2.6.0 to 2.7.0:**

Refer Release Notes for [CIS v2.7.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#270)

**_Functionality Change:_**

* Tenant based AS3 declarations support for configmaps using --filter-tenants deployment option.

### **Upgrading from 2.7.0 to 2.7.1:**

Refer Release Notes for [CIS v2.7.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#271)

**_Functionality Change:_**

* FIC installation using Helm Charts, Refer [Documentation](https://github.com/F5Networks/f5-ipam-controller/blob/main/helm-charts/f5-ipam-controller/README.md) 
* FIC installation using OpenShift Operator

### **Upgrading from 2.7.1 to 2.8.0:**

Refer Release Notes for [CIS v2.8.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst#280)

**_Functionality Change:_**

* NodePortLocal(NPL) antrea cni feature support added to Ingress and CRD Resources
* Persistence Profile support for VirtualServer, TransportServer and Policy CRs

### **Upgrading from 2.8.1 to 2.9.0:**

Refer Release Notes for [CIS v2.9.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)

**_Functionality Change:_**

* TCP Client and Server support for VirtualServer, TransportServer and Policy CRs
* Support for GTM pools priority order with global-availability load balancing method

**_Configuration Change:_**

* Setting TCP Profile in Policy CRD changed to support TCP Client and Server profiles. (See [documentation](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/Policy))
* Setting pool priority order in EDNS CRD requires a CRD schema update. (See [documentation](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/ExternalDNS))

### **Upgrading from 2.9.0 to 2.9.1:**

Refer Release Notes for [CIS v2.9.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)

### **Upgrading from 2.9.1 to 2.10.0:**

Refer Release Notes for [CIS v2.10.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)

### **Upgrading from 2.10.0 to 2.10.1:**

Refer Release Notes for [CIS v2.10.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)

**_Functionality Change:_**

* Either secure or insecure virtual server added as EDNS pool member with Ingresslink, instead of both.

### **Upgrading from 2.10.1 to 2.11.0:**

**_Functionality Change:_**

* From 2.11, if TLSProfile has multiple domains in hosts parameter then traffic is handled for all those domains on virtualserver it attached to.  

Refer Release Notes for [CIS v2.11.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)

### **Upgrading from 2.11.0 to 2.11.1:**

Refer Release Notes for [CIS v2.11.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)

**_Configuration Change:_**
* Add pattern definition in CR schema to align with F5 BIGIP object naming convention.
* RBAC changes to read the openshift network config
* Moving to CIS > 2.11.1 requires an update to RBAC and CR schema definition. See [RBAC](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/rbac/clusterrole.yaml) and [CR schema](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml) 

### **Upgrading from 2.11.1 to 2.12.0:**
* Deprecated extensions/v1beta1 ingress API and it's no longer processed by CIS >=2.12.Use networking.k8s.io/v1 API for ingress.
* Refer [guide](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/next-gen-routes/migration-guide.md) to migrate to next generation routes.
* Deprecated CommonName support for host certificate verification in secrets, use subject alternative name(SAN) in certificates instead.

### **Upgrading from 2.12.0 to 2.12.1:**
* CIS is supporting new partition for GTM in AS3 mode for CRDs. In CCCL mode there are no partition changes for GTM, common partition remains same
   * In AS3 mode, CIS will clear existing GTM objects in default partition and recreates them in new GTM partition 
   * Format of the new GTM partition name - {defaultpartition_gtm}
   * With EDNS and VS/TS/IngressLink resource partition change, sometimes CIS might come across 422 error 
     * The root cause can be VS list is not refreshed in the GSLB server.
   *  **_Migration Steps for "Transitioning from CCCL GTM Agent to AS3 GTM Agent"_**


           Step #1: 
             Prior to transitioning to the AS3 GTM Agent, it is essential to manually remove the GTM objects managed by CIS in the 'Common' Partition. 
             This is particularly important in AS3 GTM Mode, where these same GTM Pool members will be used in a distinct BIGIP partition i.e.  {defaultpartition_gtm} or 'CIS_Managed_Partition_gtm' 
             Failing to do so may result in the following error:
               2023/04/04 10:20:07 [DEBUG] [AS3] posting request to https://10.x.x.x/mgmt/shared/appsvcs/declare/test,test_gtm
               2023/04/04 10:20:36 [ERROR] [AS3] Error response from BIG-IP: code: 422 --- tenant:test_gtm --- message: declaration failed

             To remove GTM objects in the 'Common' Partition, execute the following commands, ensuring you only remove GTM objects associated with the 'Common' Partition:
               root@(localhost)(cfg-sync Standalone)(Active)(/Common)(tmos)# delete gtm wideip a all
               root@(localhost)(cfg-sync Standalone)(Active)(/Common)(tmos)# delete gtm pool a all
               Note: Additionally, delete any CIS configured monitors from the 'Common' Partition.

           Step #2:
             Once the GTM objects managed by earlier CIS have been successfully removed, initiate CIS in AS3 GTM Mode using the deployment parameter '--cccl-gtm-agent=false':
             This process ensures a smooth transition to the AS3 GTM Agent.
             Below is the successful CIS logs for reference.
               2023/04/04 10:30:49 [DEBUG] [AS3] posting request to https://10.x.x.x/mgmt/shared/appsvcs/declare/test,test_gtm
               2023/04/04 10:31:19 [DEBUG] [AS3] Response from BIG-IP: code: 200 --- tenant:test --- message: success
               2023/04/04 10:31:19 [DEBUG] [AS3] Response from BIG-IP: code: 200 --- tenant:test_gtm --- message: success

### **Upgrading from 2.12.1 to 2.13.0:**

* Upgrade the CRD schema using [CRD Update Guide](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResourceDefinitions/crd_update.md), if you are using custom resources.

* **_Functionality Change:_**
  * In AS3 >= v3.44 & CIS >= 2.13.0, CIS sets the first SSL profile (sorted in alphabetical order of their names) as default profile for SNI if multiple client SSL certificates used for a VS as kubernetes secrets. AS3 used to set the default SNI in earlier version.

* **_Configuration Change:_**
  * CIS extended to leverage server-side http2 profile on virtual Server which requires modification in the existing Policy CRD in case of using http2 functionality.
    * Please change the PolicyCRD accordingly with this [example](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResource/Policy/sample-policy.yaml)
  * In NextGen route mode CIS supports setting client and server ssl profiles from policy
    * This setting is exclusive for NextGen route mode and not applicable for CRD resources
    * Policy level ssl profiles will have the highest precedence and will override route level profiles
    * In CRD mode CIS will process ssl profiles from tls profile

### **Upgrading from 2.13.0 to 2.13.1:**

Refer Release Notes for [CIS v2.13.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)


### **Upgrading from 2.13.1 to 2.14.0:**

* Wildcard support provided in the EDNS custom resource. 
* With wildcard domain in EDNS, CIS will try to check for the exact match of wildcard host in VS/TS crds

  | EDNS Domain | VS Domain   | Matched     | 
  |-------------|-------------|-------------|
  | *.foo.com   | *.foo.com   | yes         | 
  | *.foo.com   | abc.foo.com | not matched | 

### **Upgrading from 2.14.0 to 2.15.0:**
* Disabled default health monitoring with routes, use autoMonitor support for NextGenRoutes. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/next-gen-routes/configmap/extendedRouteConfigwithBaseConfigWithAutoMonitor.yaml>`_
*  `Issue 777 <https://github.com/F5Networks/f5-appsvcs-extension/issues/777>`_: Cluster adminState in multiCluster mode doesn't work properly with AS3 (v3.47 and v3.48) as updating pool member adminState from enable to offline fails with 422 error with AS3 (v3.47 and v3.48). If customer needs this feature, we recommend to use AS3 v3.46 or lower on BIGIP.
  
Refer Release Notes for [CIS v2.15](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)

### **Upgrading from 2.15.0 to 2.15.1:**
* `Issue 3160 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3160>`_: Support to provide different IPs for the same resources deployed in different clusters for Infoblox IPAM provider only.
   ```
   Note: Remove the ipam CR created by previous version of CIS before enabling this --ipam-cluster-label parameter```
   eg: kubectl -n kube-system delete ipam <CIS_deployment_name>.<CIS_managed_bigip_partition>.ipam
   ```

Refer Release Notes for [CIS v2.15.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)

### **Upgrading from 2.15.1 to 2.16.0:**

**_Functionality Changes:_**

* For Multicluster, the **serviceName** replaced with **service** and **port** replaced with **servicePort** in the extendedServiceReferences.
* Until 2.15.1 for CRD,NextGen CIS deploy parameter "--insecure" default value is considered as true. 
* From 2.16 for CRD,NextGen "--insecure" default value will be considered as false. Which means http client will cross verify the BIGIP server certificate. 
* This is a breaking change. If "trusted-certs-cfgmap" deployment parameter is not configured, CIS might crash with error "x509: certificate signed by unknown authority". 
* Its recommend to configure "trusted-certs-cfgmap". To disable default behaviour, explicitly set "--insecure=true" flag to true in CIS deployment.

Refer Release Notes for [CIS v2.16.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)


### **Upgrading from 2.16.0 to 2.16.1:**

Refer Release Notes for [CIS v2.16.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)


### **Upgrading from 2.16.1 to 2.17.0:**

Refer Release Notes for [CIS v2.17.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst)

### **Upgrading from 2.17.0 to 2.17.1:**

**_Functionality Changes:_**

* From 2.17.0, re-sync period for service in hub mode is same as periodic-sync-interval configured in the CIS deployment parameter *periodic-sync-interval*. For which the default value is 30 seconds. Earlier it was 30 seconds.
* If --ipam-cluster-label is already enabled with previous versions, it's recommended to remove the ipam CR created by previous version of CIS and recreate again
    eg: kubectl -n kube-system delete ipam <CIS_deployment_name>.<CIS_managed_bigip_partition>.ipam
  * If you want to enable --ipam-cluster-label in cis or want to modify --ipam-cluster-label config, still it's recommended to remove the ipam CR created by previous version of CIS

### **Upgrading from 2.17.1 to 2.18.0:**

**_Functionality Changes:_**
  * By default, from CIS version 2.18.0 onwards, CIS will process all the services that do not have the loadBalancerClass field set in the service spec. CIS will not process the services that have the loadBalancerClass field set in the service spec.
  * The Load Balancer Class supports all the Custom Resources (VirtualServer, TransportServer, and IngressLink) and the loadBalancer service, and you cannot disable it. You need to either remove the loadBalancerClass field from the service or configure the CIS deployment parameter `load-balancer-class` to the same value as the loadBalancerClass field in the service.
  * Also see the deployment parameter `manage-load-balancer-class-only`, to control the behavior of CIS for services with loadBalancerClass field set in the service spec.

### **Upgrading from 2.18.0 to 2.18.1:**

**_Functionality Changes:_**
* Improved the resource status for Virtual Server, Transport Server, and Ingresslink, please upgrade the CRD schema using [CRD Update Guide](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResourceDefinitions/crd_update.md)

### **Upgrading from 2.18.1 to 2.19.0:**

**_Functionality Changes:_**
* Multi Cluster CRD
  * The --local-cluster-name parameter is a new mandatory requirement for multi-cluster mode and applies to all modes, including default, active-active, and ratio.
  * If the extended configMap does not specify a mode, CIS defaults to the Default mode for multi-cluster.
  * CIS now does the service discovery for VS/TS CR in all the clusters defined via extended configMap in active-active or ratio mode.
  * CIS 2.19.0 release no longer supports active-standby mode. Use active-active mode instead.
  * CIS no longer supports the extendedServiceReferences property for VirtualServer and TransportServer CRs in active-active and ratio modes.
* CRD
  * You cannot add or delete the serviceAddress property for VS and TS CR after creating the CR.

### **Upgrading from 2.19.0 to 2.20.0:**

**_Functionality Changes:_**
* Multi Cluster CRD
  * HTTPS protocol is supported for primaryEndPoint url. We recommend configuring the required certificates in the "trusted-certs-cfgmap" deployment parameter to ensure secure communication.
* CRD
  * CIS 2.20 and above will no longer update the  status of custom resources it's not monitoring (those with non-matching labels).
    This prevents conflicts when running multiple CIS deployments in the same k8s cluster, as each deployment can now watch a
    different set of custom resources with unique labels without interfering with resources managed by other CIS instances.
  * Partition update in the CR resources is not supported and will be rejected by CRD schema validation.
    To update partition for CR resource, delete the resource and recreate with new partition.