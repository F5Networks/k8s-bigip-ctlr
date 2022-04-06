# NextGenControllerGuide(**Preview**)

This page is created to document the behaviour of NextgenController.This is a preview release which supports limited features and not recommended to be deployed in production environment.Check for Known Issues section for more info on features not supported.

## Contents

[Overview](#overview)

[Multiple VIP and Partition support for routes](#multiple-vip-and-partition-support-for-routes)

[Prerequisites](#prerequisites)

[Configuration](#configuration)

[ExtendedSpecConfigmap](#extendedspecconfigmap)

[Examples](#examples)

[Known Issues](#known-issues)

## Overview

NextGenRoute Controller uses extenedConfigMap for extending the native resources (routes/ingress). Currently routes are extended using ConfigMap in this preview release. It also adds support for multi-partition.

## Multiple VIP and Partition support for routes

* Current CIS implementation creates a single VIP and partition for all the routes configured in the cluster which impacts scalability and performance.
* This feature is implemented to add support for creating multiple VIP in bigip mapping to route groups created per namespace.
* All the routes in the namespace are treated as part of one routegroup in this preview release.
* One virtual server(VIP) is created for each routegroup and maps to each tenant on BIGIP
* CIS processes mutliple tenant information and still sends the single unified declaration to bigip to avoid multiple posts to BIGIP.
  
  **Note**: AS3 post call is formed as mgmt/shared/appsvcs/declare/tenant1,tenant2..

## Prerequisites

* Cleanup the partition in bigip ,where existing route config is deployed.
  * Use below POST call along with this AS3 declaration [Empty Declaration](AS3-empty-declaration.json) for cleanup

    mgmt/shared/appsvcs/declare

  **Note:** Please update "bigip-partition" name in AS3 declaration with partition name to be deleted

## Configuration

* Routegroup specific config for each namespace is provided as part of extendedSpec through Configmap.
* Configmap info is passed to CIS with argument --route-spec-configmap="namespace/configmap-name"
* Controller mode should be set to openshift to enable multiple VIP support(--controller-mode="openshift")

## ExtendedSpecConfigmap:

* ExtendedSpecificConfimap is used to provide common config for routegroup like virtualservername, virtualserveraddress, WAF policy etc which is applied to all routes in the group.
* Routegroup specific config for each namespace is provided as part of extendedRouteSpec in global configmap

### Global Configmap

* Global configmap provides control to the admin to create and maintain the resource configuration centrally. 
* RBAC can be used to restrict modification of global configmap by users with tenant level access.
* If any specific tenant requires modify access for routeconfig of their namespace, admin can grant access by setting **allowOverride** to true in the extendedRouteSpec of the namespace.  

### Local Configmap

* Local configmap is used to specify route config for namespace and allows tenant users access to fine tune the route config. It is processed by CIS only when allowOverride is set to true in global confimap for this namespace.
* Only one local configmap is allowed per namespace. Local configmap must have only one entry in extendedRouteSpec list and that should be the current namespace only

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
**NOTE:** label f5nr needs to be set to true on global and local configmap to be processed by CIS.

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
## Examples
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

## CIS Logs:

[AS3] posting request to https://10.145.66.20/mgmt/shared/appsvcs/declare/tenant1,tenant2

[AS3] Response from BIG-IP: code: 200 --- tenant:tenant1 --- message: success

[AS3] Response from BIG-IP: code: 200 --- tenant:tenant2 --- message: success

## BIGIP-Config:

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
## CIS Logs:

[AS3] posting request to https://10.145.66.20/mgmt/shared/appsvcs/declare/tenant1

[AS3] Response from BIG-IP: code: 200 --- tenant:tenant1 --- message: success

## BIGIP-Config:

![partition config](bigip-config2.png?raw=true "BIGIP config")

![partition config](bigip-config3.png?raw=true "BIGIP config")

## Known issues

* CIS is allowing the insecure Traffic for all the routes when one route is having insecureEdgeTerminationPolicy policy as allow
  
* Route admit status is not being updated.

* Passthrough routes are not processed

* CIS is not processing the changes in other tenants if any one of the tenant receives 422 error

* CIS is not processing the complete route group if service is not found for any route

## FAQ
 
### Is exteneded confiMap mandatory ?
Yes. CIS fails to start without --route-spec-configmap value provided.CIS logs "invalid value provided for --route-spec-configmap" and exits
### What happens if configMap is not created or deleted?
If refrenced configmap with --route-spec-configmap is not created, CIS logs below error and doesn't process any routes

[ERROR] Unable to Get Extended Route Spec Config Map: default/global-cm, configmaps "global-cm" not found.

CIS uses cache to store extendedRouteSpec information. So, even if configmap is deleted the information loaded initially is used for route processing.
### Can i create multiple extended configmap ?
CIS only uses configmap provided through --route-spec-configmap argument. 
### Do i need to modify existing routes for extended configMap support?
No.
### What are the supported routes?
Currently supports edge routes
### Do we support bigIP referenced SSL Profiles and health monitor on routes?
currently HM and ssl profiles is not supported, will be added in future release through extended ConfigMap. Config from annotation is not considered for the NextGenController.
### Any changes in RBAC? 
No.

