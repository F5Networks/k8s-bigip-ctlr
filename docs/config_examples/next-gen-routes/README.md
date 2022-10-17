# NextGenControllerGuide(**Preview**)

This page documents the behaviour of NextgenController. This is a preview release which supports limited features and not recommended to use in production environment. Check for Known Issues section for more info on features not supported.

## Contents

[Overview](#overview)

[Multiple VIP and Partition support for routes](#multiple-vip-and-partition-support-for-routes)

[Prerequisites](#prerequisites)

[Configuration](#configuration)

[ExtendedSpecConfigmap](#extendedspecconfigmap)

[Examples](#examples)

[Known Issues](#known-issues)

## Overview

NextGenRoute Controller uses extenedConfigMap for extending the native resources (routes/ingress). Routes are extended using ConfigMap in this preview release. It also adds support for multi-partition and policy CR.

## Multiple VIP and Partition support for routes

* Current CIS implementation creates a single VIP and partition for all the routes configured.This is implemented to add support for creating multiple VIP in bigip mapping to route groups created per namespace/namespaceLabel.
* All the routes in the namespace/namespaceLabel are treated as part of one routegroup in this preview release.
* One virtual server(VIP) is created for each routegroup and maps to each tenant on BIGIP
* CIS processes mutliple tenant information and still sends the single unified declaration to bigip to avoid multiple posts to BIGIP.

  **Note**: AS3 post call is formed as mgmt/shared/appsvcs/declare/tenant1,tenant2.
  
## Policy CR support for routes
Policy CR integration with nextGenRoutes extends so many BIGIP features to the openshift routes . i.e. snat, custom tcp, http and https profiles, irules, http2 profile, persistance profile, profileMultiplex, profileL4, logProfiles, waf, botDefense, firewallPolicy, dos, allowSourceRange etc. 

## Prerequisites

* Cleanup the partition in bigip ,where existing route config is deployed.
  * Use below POST call along with this AS3 declaration [Empty Declaration](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/next-gen-routes/AS3-empty-declaration.json) for cleanup

    mgmt/shared/appsvcs/declare

  **Note:** Please update "bigip-partition" name in AS3 declaration with partition name to be deleted
* Install F5 CRDs
  - Install the F5 CRDs using following Commands:
  ```sh
  kubectl create -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml
  ```
  
## Configuration

* Routegroup specific config for each namespace/namespaceLabel is provided as part of extendedSpec through Configmap.
* Global Configmap can be set using CIS deployment argument --route-spec-configmap="namespace/configmap-name"
* Controller mode should be set to openshift to enable multiple VIP support(--controller-mode="openshift")

## ExtendedSpecConfigmap:

* ExtendedSpecificConfimap is used to provide common config for routegroup like virtualservername, virtualserveraddress, policyCR etc which is applied to all routes in the group.
* Routegroup specific config for each namespace/namespaceLabel is provided as part of extendedRouteSpec in global configmap

  
### Global Configmap

* Global configmap provides control to the admin to create and maintain the resource configuration centrally. 
* RBAC can be used to restrict modification of global configmap by users with tenant level access.
* If any specific tenant requires modify access for routeconfig of their namespace, admin can grant access by setting **allowOverride** to true in the extendedRouteSpec of the namespace.
* Base route configuration can be defined in Global ConfigMap. This cannot be overridden from local configmap. This is an alternative to CIS deployment arguments.

### Local Configmap

* Local configmap is used to specify route config for namespace and allows tenant users access to fine tune the route config. It is processed by CIS only when allowOverride is set to true in global confimap for this namespace.
* Only one local configmap is allowed per namespace. Local configmap must have only one entry in extendedRouteSpec list and that should be the current namespace only
* Local configmap is only supported when global configMap defines the routeGroup using namespace.

## Extended Route Config Parameters

### Base Route Config Parameters

Base route configuration can be defined in Global ConfigMap. This cannot be overridden from local configmap. This is an alternative to CIS deployment arguments.

| Parameter  | Required | Description                                                                                                               | Default | ConfigMap |
|------------|----------|---------------------------------------------------------------------------------------------------------------------------|---------| --------- |
| tlsCipher  | Optional | Block to define TLS cipher parameters                                                                                     | N/A     | Global configMap |
| tlsVersion | Optional | Configures TLS version to be enabled on BIG-IP. TLS 1.3 is only supported on TMOS version 14.0+.                          | 1.2     | Global configMap |
| ciphers    | Optional | Configures a ciphersuite selection string. Cipher-group and ciphers are mutually exclusive, only use one.                 | DEFAULT     | Global configMap |
| cipherGroup | Optional | Configures a cipher group in BIG-IP and reference it here. Cipher group and ciphers are mutually exclusive, only use one. | /Common/f5-default     | Global configMap |

  **Note**: 1. ciphers and cipherGroups are mutually exclusive. cipherGroup is considered for tls version 1.3 and ciphers for tls version 1.2.

### Route Group Parameters

| Parameter | Required | Description | Default | ConfigMap |
| --------- | -------- | ----------- | ------- | --------- |
| allowOverride | Optional | allow users to override the namespace config | - | Global configMap only |
| bigIpPartition | Optional | partition for creating the virtual server | partition which is defined in CIS deployment parameter | Global configMap only |
| namespaceLabel | Mandatory | namespace-label to group the routes* | - | Global configMap only |
| policyCR | Optional | Name of Policy CR to attach profiles/policies defined in it. | - | Local and Global configMap |
| namespace | Mandatory | namespace to group the routes | - | Local and Global configMap |
| vsAddress | Mandatory | BigIP Virtual Server IP Address | - | Local and Global configMap |
| vsName | Optional | Name of BigIP Virtual Server | auto | Local and Global configMap |
| tls | Optional |  Dictionary of client & server SSL profiles (See next section) | - | Local and Global configMap |

  **Note**: 1. namespaceLabel is mutually exclusive with namespace parameter
            2. --namespace-label parameter has to be defined in CIS deployment to use the namespaceLabel in extended configMap

#### TLS Config Parameters

| Parameter | Required | Description | Default | ConfigMap |
| --------- | -------- | ----------- | ------- | --------- |
| clientSSL | Optional |  client SSL profile | - | Local and Global configMap |
| serverSSL | Optional |  server SSL profile | - | Local and Global configMap |
| reference | Mandatory |  Profile Object type  | - | Local and Global configMap |

* tls schema:
```
 tls:
        clientSSL: /Common/clientssl
        serverSSL: /Common/serverssl
        reference: bigip
```

## Example Global & Local ConfigMap with namespace parameter
**Example: Global Configmap**
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
**Example: Local Configmap**
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

**Example: Global Configmap with Base Route Configuration**
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
**NOTE:** label f5nr needs to be set to true on global and local configmap to be processed by CIS.
**Note**: ciphers and cipherGroups are mutually exclusive. cipherGroup is considered for tls version 1.3 and ciphers for tls version 1.2.

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

1) Create route in tenant1 namespace
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

2) Create route in tenant2 namespace
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

You can observe tenant1 vserverName and vserverAddr are overrided by config provided in local configmap.

**Usecase2: Routes in same namespace**
  
Routes in same namepsace are grouped under single virtualserver on BIGIP

1) Create routes in tenant1 namespace
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
**Example: Global Configmap**
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
**NOTE:** label f5nr needs to be set to true on global and local configmap to be processed by CIS.

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
  
* Routes in namespace foo & bar will be mapped into single group, and a virtual server will be created in **dev** partition in bigip.
* Routes in namespace gamma & echo will be grouped together, and a virtual server will be created in **test** partition in bigip which is defined in CIS deployment.

## Legacy vs next generation routes feature comparison

Unsupported features/annotations in next-gen routes are planned to be supported in upcoming releases

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
| App-rewrite | YES | NO |
| A/B Deployment | YES | YES | 
| Policy CR | NO | YES | 

Please refer to the [examples](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes) for more details.


## Known issues
* Route status not updated when the service deleted for NextGen Routes
* CIS processes the latest local extended configMap, when there are multiple extended local configMap.
* CIS allows insecure traffic if URI path is included with CAPITAL letters for NextGen Routes
* CIS delays processing the changes in other tenants if any one of the tenant receives 422 error (takes upto 60 seconds)
* CIS is not detecting namespaceLabel update in global config map


## FAQ
 
### Is exteneded confiMap mandatory ?
Yes. CIS fails to start without `--route-spec-configmap` value provided.CIS logs `invalid value provided for --route-spec-configmap` and exits
### What happens if configMap is not created or deleted?
If referenced configmap with --route-spec-configmap is not created, CIS logs below error and doesn't process any routes
```
[ERROR] Unable to Get Extended Route Spec Config Map: default/global-cm, configmaps "global-cm" not found.
```

CIS uses cache to store extendedRouteSpec information. Even if configmap is deleted, the information loaded initially is thus used for route processing.
### Can I create multiple global extended configmap ?
CIS only uses configmap provided through --route-spec-configmap argument. 
### Do I need to modify existing routes for extended configMap support?
No.
### What are the supported routes?
edge re-encrypt & passthrough routes are supported
### What are the supported insecureEdgeTerminations?
allow, redirect & none termination supported with edge routes, while re-encrypt routes supports redirect & none terminations. 
### Do we support bigIP referenced SSL Profiles annotations on routes?
You can define SSL profiles in extended configMap.
### Can we configure health monitors using route annotations?
Yes you can continue using the health monitors using route annotations
### Which fields are optional in the extended configMap?
iRules is optional values.
### Any changes in RBAC? 
No.
### How to use policy CR with routes?
You can define the policy CR in Extended ConfigMap [See Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/Policy).



