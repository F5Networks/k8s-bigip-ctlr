CIS and IPAM Release Upgrade Process
=======================================================================

This page shows you how to upgrade from one version of CIS, IPAM. Each section shows you steps for upgrading as well as any behavioral changes. 

Refer to the [Release Notes](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst) for additional information.

Latest [RBAC](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/rbac/clusterrole.yaml) and [CR Schema](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml)

Compatibility Matrix
-------------

| CIS Version | BIG-IP Version | Kubernetes Version | OpenShift Version | AS3 Version | FIC Version | FIC Chart Version | CIS Chart Version |
|-------------|----------------|--------------------|-------------| -------------| -------------- |--------------| ------------|
| v1.14       | v15.1          | v1.16.2            | v4.2                                                          | v3.17       |             |                   | v0.0.7            |
| v2.0        | v15.1          | v1.18              | v4.3                                                          | v3.18       |             |                   | v0.0.7            |
| v2.1        | v15.1          | v1.18              | v4.4.5                                                        | v3.20       |             |                   | v0.0.7            |
| v2.1.1      | v15.1          | v1.18              | v4.5                                                          | v3.21       |             |                   | v0.0.8            |
| v2.2.0      | v15.1          | v1.18              | v4.5                                                          | v3.23       |             |                   | v0.0.9            |
| v2.2.1      | v15.1          | v1.18              | v4.6.4                                                        | v3.24       |             |                   | v0.0.10           |
| v2.2.2      | v16.0          | v1.19              | v4.6.4                                                        | v3.25       |             |                   | v0.0.11           |
| v2.3        | v16.0          | v1.19              | v4.6.4                                                        | v3.25       |             |                   | v0.0.12           |
| v2.4.0      | v16.0          | v1.20              | v4.6.4                                                        | v3.25       | v0.1.2      |                   | v0.0.13           |
| v2.4.1      | v16.0          | v1.20              | v4.6.4                                                        | v3.25       | v0.1.3      |                   | v0.0.14           |
| v2.5.0      | v16.0          | v1.21              | v4.7.13 (OpenShift SDN)                                       | v3.28       | v0.1.4      |                   | v0.0.14           |
| v2.6.0      | v16.0          | v1.21              | v4.8.12 (OpenShift SDN and OVN- Kubernetes with HyperOverlay) | v3.28       | v0.1.5      |                   | v0.0.16           |
| v2.7.0      | v16.0          | v1.22              | v4.9 (OVN)                                                    | v3.30       | v0.1.6      | v0.0.1            | v0.0.17           |
| v2.7.1      | v16.0          | v1.22              | v4.9 (OVN)                                                    | v3.30       | v0.1.6      | v0.0.1            | v0.0.18           |
| v2.8.0      | v16.0          | v1.22              | v4.9 (OVN)                                                    | v3.30       | v0.1.6      | v0.0.1            | v0.0.19           |       

CIS Features and Examples
-------------

| Feature | Example  | Description |CIS Version |
|-----------|-------------|-------- | -------|
| user-defined-as3                     | [Example](https://clouddocs.f5.com/containers/latest/userguide/config-map.html#modify-as3-configmap) | Allows users to modify AS3 ConfigMap in CIS| v2.0.0 |
| override-as3                         | [Example](https://clouddocs.f5.com/containers/latest/userguide/config-map.html#override-as3-configmap) | The Override AS3 ConfigMap hosts a part of AS3 as a configuration to be overridden. Using this ConfigMap, CIS implements the AS3 override functionality.| v2.0.0 |
| VirtualServer With TLS profile       | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServerWithTLSProfile) | VirtualServer with TLSProfile is used to specify the TLS termination. TLS termination relies on SNI. | v2.1.0 |
| virtualServer insecure               | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/unsecure-virtual-server) |Allows user to create a Virtual Server on BIG-IP with VIP.  It will load balance the traffic for domain| v2.1.1 |
| Health Monitors in EDNS              | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResource/ExternalDNS/externaldns-tcp-monitor.yaml) |Configure health monitor for GSLB pools in DNS. Heath monitor is supported for each pool members | v2.2.0 |
| virtualServer with waf               | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/waf) | By deploying this yaml file in your cluster, CIS will create a Virtual Server containing WAF policy on BIG-IP.| v2.2.0 |
| virtualServer Multiport Services     | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/MultiPortServices) | Allows to configure multiple port definitions on a Service object. | v2.2.0 |
| TransportServer with IPAM Label      | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResource/TransportServer/transport-server-with-ipamLabel/transport-with-ipamLabel.yaml) |  ipamLabel definition allows the user manage the virtual server addresss using the F5 IPAM controller.| v2.4.0 |
| TransportServer with Service address | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResource/TransportServer/ts-with-service-address.yaml)|Service address definition allows you to add a number of properties to your (virtual) server address. | v2.4.0 |
| IngressLink with IPAM Label          | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResource/IngressLink/ingressLink-with-ipamLabel/ingresslink-with-ipamLabel.yaml) | Allows users to create a IngressLink on BIG-IP with virtual server address provided by IPAM controller.| v2.6.0 |
| virtualServer with HostGroup         | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/virtual-with-hostGroup) |Allows Associated VirutalServers are grouped based on “hostGroup” parameter. MultiHost support for VS CRD is achieved using this parameter. | v2.7.0 |
| virtualServer with Wildcard domain   | [Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/virtual-with-wildcard-domain) |Allows users to create a Virtual Server on BIG-IP with wildcard domain name | v2.7.0 |
| Policy-CRD                           | [Example](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResource/Policy/sample-policy.yaml) | Policy CRD resource defines the profile configuration for a virtual server in BIG-IP. | v2.7.0 |
| Filter-Tenants                       | [Example](https://clouddocs.f5.com/containers/latest/userguide/config-map.html#filter-tenant-support-for-as3-configmap) | Uses tenant filtering API for AS3 declaration. This allows CIS to process each AS3 Tenant separately. Compatible with ConfigMap only.| v2.7.0 |

### **Upgrading from 1.14.to 2.0:**

Refer Release Notes for [CIS v2.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#20)

**_Functionality Changes:_**

* AS3 is the default agent, Requires AS3 versions>= 3.18 for 2.x releases.
* User defined AS3 Config Map in CIS watched namespaces. 
* New RH container registry : [registry.connect.redhat.com/f5networks/cntr-ingress-svcs](http://registry.connect.redhat.com/f5networks/cntr-ingress-svcs) 
* Custom Resource Definition (CRD) -Alpha available with custom resource virtual-server. [CRD Doc and Examples](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/CustomResource.md).

### **Upgrading from 2.0 to 2.1:**

Refer Release Notes for [CIS v2.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#21)

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

Refer Release Notes for [CIS v2.1.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#211)

**_Functionality Changes:_**

* Custom Resource Definition(CRD)- Preview version available with virtual server and TLSProfile custom resources. 
* Added support for installation using Helm and Operator.

### **Upgrading from 2.1.1 to 2.2.0:**

Refer Release Notes for [CIS v2.2.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#220)

**_Functionality Changes:_**

* Share Nodes implementation for CRD, Ingress and Routes. 
* IngressLink - Nginx CIS connector.

### **Upgrading from 2.2.0 to 2.2.1:**

Refer Release Notes for [CIS v2.2.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#221)

**_Functionality Changes:_**

* External DNS CRD – Preview available in CRD mode.
* ConfigMap not working for 2.2.1 
* servicePort value in ConfigMap requires the service's nodeport value 
* CRD schema definition for [External DNS](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml) and [examples](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/ExternalDNS).

### **Upgrading from 2.2.1 to 2.2.2:**

Refer Release Notes for [CIS v2.2.2](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#222)

**_Functionality Changes:_**

* CIS handles validation of BIG-IP ClientSSL/ServerSSL. 
* Virtual Server demotes from CMP when updating to CIS v 2.2.2. 
* servicePort value in ConfigMap definition needs to be equal to "service exposed port"

### **Upgrading from 2.2.2 to 2.3.0:**

Refer Release Notes for [CIS v2.3.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#230)

**_Functionality Changes:_**

* CIS supports IP address assignment to Virtual Server CRD using [F5 IPAM Controller](https://github.com/F5Networks/f5-ipam-controller/releases). Refer for [Examples](https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md).
* CIS allows user to leverage Virtual IP address using either [F5 IPAM Controller](https://github.com/F5Networks/f5-ipam-controller/releases) or virtualServerAddress field in VirtualServer CRD 
* iRule reference for VirtualServer CRDs 
* Enabling VLANS for VirtualServer and TransportServer CRDs 
* Updated CR Kind from NginxCisConnector to IngressLink 
* Helm Chart Enhancements:Added Support for [livenessProbe](https://github.com/F5Networks/charts/issues/34), [ReadinessProbe](https://github.com/F5Networks/charts/issues/34), [nodeSelectors](https://github.com/F5Networks/charts/issues/38), [tolerations](https://github.com/F5Networks/charts/issues/38). 
* Workaround for CIS in [IPAM mode](https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md).

### **Upgrading from 2.3.0 to 2.4.0:**

Refer Release Notes for [CIS v2.4.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#240)

**_Functionality Changes:_**

* CIS supports IP address assignment to kubernetes service type LoadBalancer using [F5 IPAM Controller](https://github.com/F5Networks/f5-ipam-controller/releases). Refer for [Examples](https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md). 
* CIS supports IP address assignment to TransportServer Custom Resources using [F5 IPAM Controller](https://github.com/F5Networks/f5-ipam-controller/releases). Refer for [Examples](https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md). 
* Integrated the IngressLink mode with CRD mode. 
* Helm Chart Enhancements:
  * Updated the [Custom Resource Definitions](https://raw.githubusercontent.com/F5Networks/charts/gh-pages/example_values/f5-bigip-ctlr/cis-k8s-custom-resource-values.yaml) for VirtualServer and TransportServer resources. 
  * Updated the [RBAC](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/helm-charts/f5-bigip-ctlr/templates/f5-bigip-ctlr-clusterrole.yaml) to support service type LoadBalancer.

### **Upgrading from 2.4.0 to 2.5.0:**

Refer Release Notes for [CIS v2.5.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#250)

**_Functionality Changes:_**

* Moving to CIS > 2.4.1 requires update to RBAC and CR schema definition before upgrade. See [RBAC](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/rbac/clusterrole.yaml) and [CR schema](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml) 
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

Refer Release Notes for [CIS v2.6.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#260)

**_Functionality Changes:_**

* CIS supports IP address assignment to IngressLink Custom Resources using F5 IPAM Controller(See [documentation](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/IngressLink/ingressLink-with-ipamLabel))
* CIS supports IPV6 address in bigip-url & gtm-bigip-url parameter 
* F5 IPAM Controller supports InfoBlox (See [FIC release notes](https://github.com/F5Networks/f5-ipam-controller/blob/main/docs/RELEASE-NOTES.rst))

### **Upgrading from 2.6.0 to 2.6.1:**

Refer Release Notes for [CIS v2.6.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#261)

**_Functionality Change:_**

* Moving from CIS > 2.6 with IPAM, see troubleshooting guide for IPAM issue _ipams.fic.f5.com_ not found. Refer [Troubleshooting Section](https://github.com/F5Networks/f5-ipam-controller/blob/main/docs/faq/README.md)

### **Upgrading from 2.6.0 to 2.7.0:**

Refer Release Notes for [CIS v2.7.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#270)

**_Functionality Change:_**

* Tenant based AS3 declarations support for configmaps using --filter-tenants deployment option.

### **Upgrading from 2.7.0 to 2.7.1:**

Refer Release Notes for [CIS v2.7.1](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#271)

**_Functionality Change:_**

* FIC installation using Helm Charts, Refer [Documentation](https://github.com/F5Networks/f5-ipam-controller/blob/main/helm-charts/f5-ipam-controller/README.md) 
* FIC installation using OpenShift Operator

### **Upgrading from 2.7.1 to 2.8.0:**

Refer Release Notes for [CIS v2.8.0](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/RELEASE-NOTES.rst#280)

**_Functionality Change:_**

* NodePortLocal(NPL) antrea cni feature support added to Ingress and CRD Resources
* Persistence Profile support for VirtualServer, TransportServer and Policy CRs
