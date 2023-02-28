# NextGenControllerGuide

This page documents the behaviour of NextGenController. Check the Known Issues section for more information on features not supported.
## Contents

[Overview](#overview)

[MigrationGuide](#Migration-Guide)

[Prerequisites](#prerequisites)

[Configuration](#configuration)

[ExtendedSpecConfigMap](#extendedspecconfigmap)

[Examples](#examples)

[Known Issues](#known-issues)

[FAQ](#faq)

## Overview

NextGen Controller uses extendedConfigMap for extending the native resources (routes). Routes are extended using ConfigMap in this release. NextGen Routes implementation also support for multi-partition, policy CR and externalDNS CR.
**Note**: CIS supports processing of routes in traditional way as well as with NextGen Controller.

###RouteGroup
All the routes are grouped by namespaces or namespace-labels into RouteGroups.
Each RouteGroup shares the same vsAddress, vsName, bigIpPartition and policy CR which is specified in extendedConfigMap

All the routes in the namespace/namespaceLabel are treated as part of one routegroup in this implementation

**Note**: namespace and namespace-label is mutual exclusive. That means CIS can support ExtendedConfigmap with either all RouteGroups with namespace or all with namespace-label parameter.

Below is the sample representing RouteGroups.
```
extendedRouteSpec:
- namespace: foo   -------------------------------------|
  vserverAddr: 10.8.0.4                                 |
  vserverName: nextgenroutes                            |----------------> RouteGroup with namespace
  allowOverride: true                                   |
  bigIpPartition: MultiTenant                           |
  policyCR: default/sample-policy  _____________________|
- namespace: bar -------------------------------------|
  vserverAddr: 10.8.0.5                               |----------------> RouteGroup with namespace
  allowOverride: false           _____________________|
```
```
extendedRouteSpec:
- namespaceLabel: environment=dev -------------------|
  vserverAddr: 10.8.3.11                             |
  vserverName: nextgenroutes                         |----------------> RouteGroup with namespacelabel
  bigIpPartition: dev                                |
  allowOverride: true                                |
  policyCR: default/sample-policy ___________________|                
- namespaceLabel: environment=test -----------------|
  vserverAddr: 10.8.3.12                            |----------------> RouteGroup with namespacelabel
  policyCR: default/sample-policy __________________|
```
###  Refer [Route Group Parameters Section](#Route-Group-Parameters) for more details
### Multiple VIP and Partition support for routes

* Current CIS implementation creates a single VIP and partition for all the routes configured. This is implemented to add support for creating multiple VIP in BIG-IP mapping to route groups created per namespace/namespaceLabel.
* All the routes in the namespace/namespaceLabel are treated as part of one routegroup in this implementation.
* One virtual server(VIP) is created for each routegroup and maps to defined/default tenant on BIG-IP.
* CIS processes multiple tenant information and still sends the single unified declaration to BIG-IP to avoid multiple posts to BIG-IP.

  **Note**: AS3 post call is formed as mgmt/shared/appsvcs/declare/tenant1,tenant2.

### GSLB support for routes
**Prerequisite**: AS3 Version >= 3.41.0 to use EDNS feature.
For every EDNS resource created, CIS will add VS having matching domain as the Wide IP pool member.

### Policy CR support for routes
Policy CR integration with nextGenRoutes extends so many BIG-IP features to the Openshift routes, i.e. snat, custom tcp, http and https profiles, irules, http2 profile, persistance profile, profileMultiplex, profileL4, logProfiles, waf, botDefense, firewallPolicy, dos, allowSourceRange, etc.

### WAF precedence 
WAF can be specified either in route annotations or in policy CR.
If it's specified in both the places then WAF in policy CR has more precedence over annotation, however with allowOverride field set to true in the route group in Extended configmap, WAF in route annotation will have more precedence.
WAF specified in route annotations configures WAF at LTM Policy, whereas WAF in Policy CR configures WAF at VirtualServer(VIP) Level

### Allow source range precedence
Allow source range can be specified either in route annotations or in policy CR.
If it's specified in both the places then allow source range in policy CR has more precedence over annotation, however with allowOverride field set to true in the route group in Extended configmap, allow source range in route annotation will have more precedence.

### SSL Profiles precedence
* SSL can be specified in route as certificate(spec certs), route annotation as bigip reference/secret or as default SSL profiles in global configmap. 
* If route is defined with both certificate(spec certs) and SSL annotation then route annotation will have more precedence followed by route certificate(spec certs). Default SSL profiles in global configmap will have the least precedence.
* Route with SSL profiles annotation reference to bigip [Example](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/next-gen-routes/routes/reencrypt-route-with-bigip-reference-in-ssl-annotaion.yaml)
* Route with SSL profiles annotation reference to secret [Example](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/next-gen-routes/routes/reencrypt-route-with-k8s-secret-in-ssl-annotation.yaml)
* Global configmap with defaultTLS [Example](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/next-gen-routes/configmap/extendedRouteConfigwithBaseConfig.yaml)

### Support for Health Monitors from pod liveness probe
CIS uses the liveness probe of the pods to form the health monitors, whenever health annotations not provided in the route annotations. 

## Migration Guide
Follow this for easy migration [Migration Guide](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/next-gen-routes/migration-guide.md)

## Prerequisites

* Clean up the partition in BIG-IP, where the existing route config is deployed.
  * Use the POST Method with below endpoint along with this AS3 declaration [Empty Declaration](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/next-gen-routes/AS3-empty-declaration.json) for cleanup.

    mgmt/shared/appsvcs/declare

  **Note:** Please update "bigip-partition" name in AS3 declaration with the partition name to be deleted.
* Install F5 CRDs:
  - Install the F5 CRDs using following Commands:
  ```sh
  kubectl create -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml
  ```
  
## Configuration

* Routegroup specific config for each namespace/namespaceLabel is provided as part of extendedSpec through ConfigMap.
* Global ConfigMap can be set using CIS deployment argument --route-spec-configmap="namespace/configmap-name"
* Controller mode should be set to Openshift to enable multiple VIP support(--controller-mode="openshift")

## Extended Spec ConfigMap:

* Extended spec ConfigMap is used to provide common config for routegroup like virtualservername, virtualserveraddress, policyCR, etc., which is applied to all routes in the group.
* Routegroup specific config for each namespace/namespaceLabel is provided as part of extendedRouteSpec in global ConfigMap.

  
### Global ConfigMap

* Global ConfigMap provides control to the admin to create and maintain the resource configuration centrally. 
* RBAC can be used to restrict modification of global ConfigMap by users with tenant level access.
* If any specific tenant requires modify access for routeconfig of their namespace, the admin can grant access by setting **allowOverride** to true in the extendedRouteSpec of the namespace.
* Base route configuration can be defined in Global ConfigMap. This cannot be overridden from local ConfigMap. This is an alternative to CIS deployment arguments.

### Local ConfigMap

* Local ConfigMap is used to specify route config for namespace and allows tenant users access to fine-tune the route config. It is processed by CIS only when allowOverride is set to true in global ConfigMap for this namespace.
* Only one local ConfigMap is allowed per namespace. Local ConfigMap must have only one entry in the extendedRouteSpec list and that should be the current namespace only.
* Local ConfigMap is only supported when global ConfigMap defines the routeGroup using namespace.

## Extended Route Config Parameters

### Base Route Config Parameters

Base route configuration can be defined in Global ConfigMap. This cannot be overridden from local ConfigMap. This is an alternative to CIS deployment arguments.

| Parameter   | Required | Description                                                                                                               | Default | ConfigMap |
|-------------|----------|---------------------------------------------------------------------------------------------------------------------------|---------| --------- |
| tlsCipher   | Optional | Block to define TLS cipher parameters                                                                                     | N/A     | Global ConfigMap |
| defaultTLS | Optional | Configures a cipher group in BIG-IP and references it here. Cipher group and ciphers are mutually exclusive; only use one. | /Common/f5-default     | Global ConfigMap |

```
 tlsCipher:
    tlsVersion: 1.3
    cipherGroup: /Common/f5-default
```

**Note**: 1. ciphers and cipherGroups are mutually exclusive. cipherGroup is considered for tls version 1.3 and ciphers for tls version 1.2.

#### tlsCipher Config Parameters
| Parameter   | Required | Description                                                                                                               | Default | ConfigMap |
|-------------|----------|---------------------------------------------------------------------------------------------------------------------------|---------| --------- |
| tlsVersion  | Optional | Configures TLS version to be enabled on BIG-IP. TLS 1.3 is only supported on TMOS version 14.0+.                          | 1.2     | Global ConfigMap |
| ciphers     | Optional | Configures a ciphersuite selection string. Cipher-group and ciphers are mutually exclusive; only use one.                 | DEFAULT     | Global ConfigMap |
| cipherGroup | Optional | Configures a cipher group in BIG-IP and references it here. Cipher group and ciphers are mutually exclusive; only use one. | /Common/f5-default     | Global ConfigMap |

#### defaultTLS Config Parameters

| Parameter | Required | Description | Default | ConfigMap |
| --------- | -------- | ----------- | ------- | --------- |
| clientSSL | Optional |  client SSL profile | - | Global ConfigMap |
| serverSSL | Optional |  server SSL profile | - | Global ConfigMap |
| reference | Mandatory |  Profile Object type  | - | Global ConfigMap |

* defaultTLS schema:
```
 defaultTLS:
    clientSSL: /Common/clientssl
    serverSSL: /Common/serverssl
    reference: bigip
```

### Route Group Parameters

| Parameter | Required | Description | Default | ConfigMap |
| --------- | -------- | ----------- | ------- | --------- |
| allowOverride | Optional | Allow users to override the namespace config | - | Global ConfigMap only |
| bigIpPartition | Optional | Partition for creating the virtual server | Partition which is defined in CIS deployment parameter | Global ConfigMap only |
| namespaceLabel | Mandatory | namespace-label to group the routes* | - | Global ConfigMap only |
| policyCR | Optional | Name of Policy CR to attach profiles/policies defined in it. | - | Local and Global ConfigMap |
| namespace | Mandatory | namespace to group the routes | - | Local and Global ConfigMap |
| vsAddress | Mandatory | BigIP Virtual Server IP Address | - | Local and Global ConfigMap |
| vsName | Optional | Name of BigIP Virtual Server | auto | Local and Global ConfigMap |

  **Note**: 1. namespaceLabel is mutually exclusive with namespace parameter.
            2. --namespace-label parameter has to be defined in CIS deployment to use the namespaceLabel in extended ConfigMap.


## Example Global & Local ConfigMap with namespace parameter
**Example: Global ConfigMap**
```
apiVersion: v1
data:
  extendedSpec: |
    extendedRouteSpec:
    - namespace: tenant1
      vserverAddr: 10.8.3.130
      vserverName: routetenant1
      allowOverride: true
      bigIpPartition: tenant1
      policyCR: default/sample-policy
    - namespace: tenant2
      vserverAddr: 10.8.3.132
      vserverName: routetenant2
      bigIpPartition: tenant2
kind: ConfigMap
metadata:
  labels:
    f5nr: "true"
  name: global-cm
  namespace: default
```
**Example: Local ConfigMap**
```
apiVersion: v1
data:
  extendedSpec: |
    extendedRouteSpec:
    - namespace: tenant1
      vserverAddr: 10.8.3.137
      vserverName: routetenantoverride
kind: ConfigMap
metadata:
  labels:
    f5nr: "true"
  name: extended-route-spec
  namespace: tenant1
```

**Example: Global ConfigMap with Base Route Configuration**
```
apiVersion: v1
data:
  extendedSpec: |
    baseRouteSpec:
     tlsCipher:
      tlsVersion: 1.2
      ciphers: DEFAULT
      cipherGroup: /Common/f5-default
    extendedRouteSpec:
    - namespace: tenant1
      vserverAddr: 10.8.3.130
      vserverName: routetenant1
      allowOverride: true
    - namespace: tenant2
      vserverAddr: 10.8.3.132
      vserverName: routetenant2
kind: ConfigMap
metadata:
  labels:
    f5nr: "true"
  name: global-cm
  namespace: default
```
**NOTE:** The label f5nr needs to be set to true on global and local ConfigMap to be processed by CIS.
**Note** ciphers and cipherGroups are mutually exclusive. cipherGroup is considered for tls version 1.3 and ciphers for tls version 1.2.

Cis args:
````  
  - --route-spec-configmap
  - default/global-cm
  - --controller-mode
  - openshift
````
Example CIS Deployment:
```
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
  labels:
    name: test-bigip-controller
  name: test-bigip-controller
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: test-bigip-controller
    spec:
      containers:
      - args:
        - --bigip-partition
        - <partition>
        - --bigip-url
        - <ip_address-or-hostname>
        - --bigip-username
        - <username>
        - --bigip-password
        - <password>
        - --as3-validation=true
        - --disable-teems=true
        - --insecure
        - --route-label=systest
        - --route-spec-configmap
        - default/global-cm
        - --controller-mode
        - openshift
        - --openshift-sdn-name
        - /test/vxlan-tunnel-mp
        - --pool-member-type
        - cluster
        command:
        - /app/bin/k8s-bigip-ctlr
        image: f5networks/k8s-bigip-ctlr:latest
        imagePullPolicy: Always
        name: test-bigip-controller
      serviceAccount: bigip-controller
      serviceAccountName: bigip-controller
```

**Usecase1: Routes in different namespace**

1) Create a route in the tenant1 namespace:
```
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  labels:
    f5type: systest
  name: svc-oss-edge-spec-1
  namespace: tenant1
spec:
  host: pytest-oss-edge-spec-1.com
  path: /tenant1
  tls:
    certificate: |
      -----BEGIN CERTIFICATE-----
      -----END CERTIFICATE-----
    key: |
      -----BEGIN RSA PRIVATE KEY-----
      -----END RSA PRIVATE KEY-----
    termination: edge
  to:
    kind: Service
    name: svc-1
    weight: 100
  wildcardPolicy: None
```

2) Create a route in the tenant2 namespace:
```
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  labels:
    f5type: systest
  name: svc-oss-edge-spec-2
  namespace: tenant2
spec:
  host: pytest-oss-edge-spec-2.com
  path: /tenant2
  tls:
    certificate: |
      -----BEGIN CERTIFICATE-----
      -----END CERTIFICATE-----
    key: |
      -----BEGIN RSA PRIVATE KEY-----
      -----END RSA PRIVATE KEY-----
    termination: edge
  to:
    kind: Service
    name: svc-2
    weight: 100
  wildcardPolicy: None

```

### CIS Logs:

[AS3] posting request to https://10.145.66.20/mgmt/shared/appsvcs/declare/tenant1,tenant2

[AS3] Response from BIG-IP: code: 200 --- tenant:tenant1 --- message: success

[AS3] Response from BIG-IP: code: 200 --- tenant:tenant2 --- message: success

### BIGIP-Config:

![partition config](bigip-config.png?raw=true "BIGIP config")

You can observe tenant1 vserverName and vserverAddr are overrided by config provided in local ConfigMap.

**Usecase2: Routes in same namespace**
  
Routes in same namepsace are grouped under single virtualserver on BIG-IP.

1) Create routes in tenant1 namespace:
```
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  labels:
    f5type: systest
  name: svc-oss-edge-spec-1
  namespace: tenant1
spec:
  host: pytest-oss-edge-spec-1.com
  path: /tenant1
  tls:
    certificate: |
      -----BEGIN CERTIFICATE-----
      -----END CERTIFICATE-----
    key: |
      -----BEGIN RSA PRIVATE KEY-----
      -----END RSA PRIVATE KEY-----
    termination: edge
  to:
    kind: Service
    name: svc-1
    weight: 100
  wildcardPolicy: None
```
```
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  labels:
    f5type: systest
  name: svc-oss-edge-spec-2
  namespace: tenant1
spec:
  host: pytest-oss-edge-spec-2.com
  path: /test
  tls:
    certificate: |
      -----BEGIN CERTIFICATE-----
      -----END CERTIFICATE-----
    key: |
      -----BEGIN RSA PRIVATE KEY-----
      -----END RSA PRIVATE KEY-----
    termination: edge
  to:
    kind: Service
    name: svc-2
    weight: 100
  wildcardPolicy: None
```
### CIS Logs:

[AS3] posting request to https://10.145.66.20/mgmt/shared/appsvcs/declare/tenant1

[AS3] Response from BIG-IP: code: 200 --- tenant:tenant1 --- message: success

### BIGIP-Config:

![partition config](bigip-config2.png?raw=true "BIGIP config")

![partition config](bigip-config3.png?raw=true "BIGIP config")

## Example Global ConfigMap with namespaceLabel parameter
**Example: Global ConfigMap**
```
apiVersion: v1
data:
  extendedSpec: |
    extendedRouteSpec:
    - namespaceLabel: routegroup=group1
      vserverAddr: 10.8.3.130
      vserverName: routetenant1
      allowOverride: true
      bigIpPartition: dev
    - namespaceLabel: routegroup=group2
      vserverAddr: 10.8.3.132
      vserverName: routetenant2
kind: ConfigMap
metadata:
  labels:
    f5nr: "true"
  name: global-cm
  namespace: default
```
**NOTE:** The label f5nr needs to be set to true on global and local ConfigMap to be processed by CIS.

Cis args:
````  
  - --route-spec-configmap
  - default/global-cm
  - --controller-mode
  - openshift
  - --namespace-label=environement=dev
````
Example CIS Deployment:
```
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
  labels:
    name: test-bigip-controller
  name: test-bigip-controller
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: test-bigip-controller
    spec:
      containers:
      - args:
        - --bigip-partition
        - test
        - --bigip-url
        - <ip_address-or-hostname>
        - --bigip-username
        - <username>
        - --bigip-password
        - <password>
        - --as3-validation=true
        - --disable-teems=true
        - --insecure
        - --route-label=systest
        - --route-spec-configmap
        - default/global-cm
        - --controller-mode
        - openshift
        - --openshift-sdn-name
        - /test/vxlan-tunnel-mp
        - --pool-member-type
        - cluster
        - --namespace-label=environment=dev
        command:
        - /app/bin/k8s-bigip-ctlr
        image: f5networks/k8s-bigip-ctlr:latest
        imagePullPolicy: Always
        name: test-bigip-controller
      serviceAccount: bigip-controller
      serviceAccountName: bigip-controller
```
Label the namespaces:
```
  oc label namespaces foo environment=dev routegroup=group1 --overwrite=true
  oc label namespaces bar environment=dev routegroup=group1 --overwrite=true
  oc label namespaces gamma environment=dev routegroup=group2 --overwrite=true
  oc label namespaces echo environment=dev routegroup=group2 --overwrite=true
```
  
* Routes in namespace foo and bar will be mapped into a single group, and a virtual server will be created in the **dev** partition on bigip.
* Routes in namespace gamma and echo will be grouped together, and a virtual server will be created in **test** partition in bigip, which is defined in the CIS deployment.

## Example GSLB support for routes in AS3 mode


* CIS supports only AS3 for GTM in NextGen routes

1) Configure CIS args to AS3 agent:
```
- args:
- --bigip-partition
- test
- --cccl-gtm-agent=false
```

2) Create a route with a host in namespace matching route group
```
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  labels:
    name: svc1
    f5type: systest
  name: svc1-route-edge
  namespace: foo
spec:
  host: foo.com
  path: "/"
  port:
    targetPort: 443
  tls:
    certificate: |
      -----BEGIN CERTIFICATE-----
      -----END CERTIFICATE-----
    key: |
      -----BEGIN PRIVATE KEY-----
      -----END PRIVATE KEY-----
    termination: edge
  to:
    kind: Service
    name: svc1
```

3) Create a EDNS resource with domain name
```
apiVersion: "cis.f5.com/v1"
kind: ExternalDNS
metadata:
  name: exdns-foo
  labels:
    f5cr: "true"
spec:
  domainName: foo.com
  dnsRecordType: A
  loadBalanceMethod: round-robin
  pools:
  - name: pytest-foo-1.com
    dnsRecordType: A
    loadBalanceMethod: round-robin
    dataServerName: /Common/DC-SL
    monitor:
      type: https
      send: "GET /"
      recv: ""
      interval: 10
      timeout: 10
```

**Note**:
1)  Before creating EDNS resource, we need to have LTM objects on BigIP
2) CCCL mode is not supported.
3) Like CRD's, all EDNS resources will be created in default partition in BigIP

## Legacy vs next generation routes feature comparison

| Features | Legacy Routes | Next-gen Routes |
| ------ | ------ | ------ |
| Insecure | YES | YES | 
| Secure | YES | YES | 
| Health Monitors | YES | YES |
| WAF | YES | YES |
| iRules | YES | YES |
| Multiple VIP | NO | YES |
| Multiple Partition | NO | YES |
| SSL Profiles | YES | YES | 
| Load Balancing Method | YES | YES | 
| allow-source-range | YES | YES | 
| URL-rewrite | YES | YES | 
| App-rewrite | YES | YES |
| A/B Deployment | YES | YES | 
| Policy CR | NO | YES | 

Please refer to the [examples](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes) for more details.


## Known issues
* CIS processes the latest local extended ConfigMap when there are multiple extended local ConfigMap.
* CIS allows insecure traffic if the URI path is included with CAPITAL letters for NextGen Routes.
* CIS delays processing the changes in other tenants if any one of the tenant receives a 422 error (takes upto 60 seconds).
* GSLB - When there is a route group partition change, BIG-IP is taking more time to identify the VS on new partition.


## FAQ
 
### Is exteneded confiMap mandatory?
Yes. CIS fails to start without `--route-spec-configmap` value provided. CIS logs `invalid value provided for --route-spec-configmap` and exits
### What happens if ConfigMap is not created or deleted?
If referenced ConfigMap with --route-spec-configmap is not created, CIS logs below error and doesn't process any routes.
```
[ERROR] Unable to Get Extended Route Spec Config Map: default/global-cm, ConfigMaps "global-cm" not found.
```

CIS uses cache to store extendedRouteSpec information. Even if ConfigMap is deleted, the information loaded initially is thus used for route processing.
### Can I create multiple global extended ConfigMap ?
CIS only uses ConfigMap provided through --route-spec-configmap argument. 
### Do I need to modify existing routes for extended ConfigMap support?
No.
### What are the supported routes?
Edge re-encrypt and passthrough routes are supported.
### What are the supported insecureEdgeTerminations?
allow, redirect and none termination supported with edge routes, while re-encrypt routes supports redirect and none terminations. 
### Do we support bigIP referenced SSL Profiles annotations on routes?
Yes you can continue the SSL Profiles in route annotations.
### Do we support Kubernetes secrets in SSL Profiles annotations on routes?
Yes you can define the Kubernetes secret in route's SSL annotations. Please refer to [Example](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/next-gen-routes/routes/reencrypt-route-with-k8s-secret-in-ssl-annotation.yaml).
### Can we the use legacy default-client-ssl and default-server-ssl CLI parameters?
No, they are no longer supported as CLI parameters. These CLI parameters are moved to global configmap -> baseRouteSpec -> defaultTLS -> clientSSL and serverSSL.
Please refer to [Example](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/next-gen-routes/configmap/extendedRouteConfigwithBaseConfig.yaml).
### What is the precedence of client and server SSL profiles? 
CIS considers following precedence order.  Route annotations have the highest priority( followed by) route certificates(spec certs) have next priority (followed by) global configmap baseRouteSpec default profiles.
### What is not supported with the SSL profiles?
Under a single route group or single VIP, a combination of routes having route certificates(spec certs) and routes with SSL profiles annotation with bigip reference are not supported.
### Can we configure health monitors using route annotations?
Yes you can continue using the health monitors in route annotations.
### Can we configure waf using route annotations?
Yes you can continue using the waf in route annotations.
### Can we configure allowSourceRange using route annotations?
Yes you can continue using the allowSourceRange in route annotations.
### Can we configure rewriteAppRoot using route annotations?
Yes you can continue using the rewriteAppRoot in route annotations.
### Any changes in RBAC? 
No.
### How do I use policy CR with routes?
You can define the policy CR in Extended ConfigMap [See Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/Policy).



