# Migrating to NextGen Routes

### Contents

[Overview](#overview)

[Prerequisites](#prerequisites)

[Migration Tool](#MigrationTool)

[Deprecated Annotations](#deprecated-annotations)

[Example Migration to nextGen Routes](#example-migration-to-nextgen-routes)


## Overview
NextGenRoute Controller uses extendedConfigMap for extending the native resources (routes). All the routes are group by namespaces or namespace-labels into RouteGroups. Each RouteGroup shares the same vsAddress, vsName and policy CR  which is specified in extendedConfigMap. 
In order to migrate to nextGen we first need to create an extended ConfigMap and policy CR then modify the CIS deployment accordingly. Refer [NextGen Route Documentation](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/next-gen-routes) for more details

## Migration using defaultRouteGroup
Currently, RouteGroup are expected to define per namespace or namespace label as follows:
```
extendedRouteSpec:
- namespace: foo
  vserverAddr: 10.8.0.4
  vserverName: nextgenroutes
  allowOverride: true
- namespace: bar
  vserverAddr: 10.8.0.5
  allowOverride: false
```
```
extendedRouteSpec:
- namespaceLabel: environment=dev
  vserverAddr: 10.8.3.11
  vserverName: nextgenroutes
  bigIpPartition: dev
  policyCR: default/sample-policy
- namespaceLabel: environment=test
  vserverAddr: 10.8.3.12
  policyCR: default/sample-policy
```

In legacy routes, all http/https routes grouped into a single virtual server on BIGIP. Following CIS deployment args are used for the legacy virtual server creation:

```
route-http-vserver - vserverName for http server

route-https-vserver - vserverName for https server

route-vserver-addr - vserver address
```


In nextgen controller, we can provide the same servername and address in baseRouteSpec using defaultRouteGroup as follows:
```
data:
  extendedSpec: |
    baseRouteSpec:
     tlsCipher:
       tlsVersion: 1.2
       ciphers: DEFAULT
       cipherGroup: /Common/f5-default
     defaultTLS:
       clientSSL: /Common/clientssl
       serverSSL: /Common/serverssl
       reference: bigip
     defaultRouteGroup:
       vserverAddr: 10.8.0.10
       vserverName: ose_server
       policyCR: ""
```

#### defaultRouteGroup Config Parameters
| Parameter   | Required | Description                                                                                                               |
|-------------|----------|---------------------------------------------------------------|
| vserverAddr  | Mandatory | Bind address for virtual server for OpenShift Route objects.|
| vserverName     | Mandatory | The name of the http virtual server for OpenShift Routes.|
| policyCR | Optional | Name of Policy CR to attach profiles/policies defined in it.       |

**Note**: 
  1. defaultRouteGroup and extendedRouteSpec are mutually exclusive.Error out on extendedConfigMap processing with invalid configuration error.
  2. https virtual server name will be automatically created using vserverName i.e. <vserverName>_<https_port_no>.

## Prerequisites
Stop the running CIS.

## MigrationTool
* This tool helps in migrating from Legacy Routes to nextGenRoutes and generates the required ExtendedConfigmap, policyCR(if as3 override configmap file is provided) and CIS deployment file which can be used to migrate to nextGenRoutes mode. [NextGenMigrationTool](https://github.com/f5devcentral/f5-cis-docs/tree/main/nextgen-route-migration)

## Example Migration to nextGen Routes

### Old Configuration

Consider CIS configured to manage Routes with following configuration.

CIS Deployment Arguments:

```
    args: [
      "--bigip-username=admin",
      "--bigip-password=admin",
      "--bigip-url=10.10.10.20",
      "--bigip-partition=openshift",
      "--pool-member-type=cluster",
      "--openshift-sdn-name=/Common/openshift_vxlan",
      "--manage-routes=true",
      "--namespace=f5demo",
      "--namespace=f5demo2",
      "--route-vserver-addr=10.192.75.107",
      "--log-level=DEBUG",
      "--log-as3-response=true",
      "--route-http-vserver=test_unsecure_vs",
      "--route-https-vserver=test_secure_vs",
      "--default-client-ssl=/Common/clientssl",
      "--default-server-ssl=/Common/serverssl",
      "--tls-version=1.3",
      "--cipher-group=/Common/f5-default",
      "--insecure=true",
      "--route-label=f5type=systest",
      ]
```

Sample Route:

    ```
    apiVersion: route.openshift.io/v1
    kind: Route
    metadata:
      annotations:
        virtual-server.f5.com/clientssl: /Common/bar-clientssl
        virtual-server.f5.com/serverssl: /Common/bar-serverssl
        virtual-server.f5.com/balance: least-connections-node
        virtual-server.f5.com/allow-source-range: "1.2.3.4/32,2.2.2.0/24"
        virtual-server.f5.com/waf: /Common/WAF_Policy
        virtual-server.f5.com/health: |
          [
            {
              "path": "pytest-bar-1.com/",
              "send": "HTTP GET /",
              "interval": 5,
              "timeout": 10
            }
          ]
      labels:
        f5type: systest
      name: svc-pytest-bar-1-com
      namespace: f5demo
    spec:
      host: pytest-bar-1.com
      path: /
      tls:
        termination: edge
      to:
        kind: Service
        name: svc-pytest-bar-1-com
        weight: 100
      wildcardPolicy: None
    ```

### Migrating to NextGenRoutes
#### Step-1: Install the CRDs
  - Install the F5 CRDs using following Commands:

    ```sh
    export CIS_VERSION=<cis-version>
    # For example
    # export CIS_VERSION=v2.12.0
    kubectl create -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/${CIS_VERSION}/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml
    ```

#### Step-2 Creating Extended ConfigMap using defaultRouteGroup

Extended ConfigMap is a must-use with the nextGen Route Controller. Refer [Documentation](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/next-gen-routes) for more details          

You can create an extended ConfigMap for given example as follows:
* You can define the vserverAddr same as "route-vserver-addr" parameter in CIS deployment.

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: extended-spec-config
  namespace: f5demo2
data:
    extendedSpec: |
      baseRouteSpec:
       tlsCipher:
         tlsVersion: 1.3
         cipherGroup: /Common/f5-default 
       defaultTLS:
         clientSSL: /Common/clientssl
         serverSSL: /Common/serverssl
         reference: bigip
       defaultRouteGroup:
         vserverAddr: 10.192.75.107
         vserverName: ose_server
         policyCR: 
```
  
**Note**: Make sure the namespace where we created the ConfigMap monitored by CIS.

#### Step-3: Prepare the Policy CR (Optional)
It's an optional step you can continue using WAF and AllowSourceRange annotations in routes. You can create the Policy CR as follows for WAF and AllowSourceRange annotations:

```
apiVersion: cis.f5.com/v1
kind: Policy
metadata:
  labels:
    f5cr: "true"
  name: sample-policy
  namespace: f5demo2
spec:
  l7Policies:
    waf: /Common/WAF_Policy
  l3Policies:
    allowSourceRange:
      - 1.2.3.4/32
      - 2.2.2.0/24
```

**Note**:
    * If WAF/AllowSourceRange is defined in both route annotation & policy CR, route annotation takes the priority by default.  
    * You can use the Policy CR to extend the virtual server capabilities even more. [See Details](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/Policy).
    * Make sure the namespace where we created the policy CR monitored by CIS.   
 
#### Step-4 Update the CIS deployment parameters and start
* Configure --controller-mode: openshift to use NextGen Route controller in CIS.

```
    - --controller-mode
    - openshift
```

* Configure extended ConfigMap and specify that in the CIS deployment parameter.
    
```
    - --extended-spec-configmap
    - f5demo2/extended-spec-config
```

* Remove "route-vserver-addr" parameter from CIS deployment and define as vserverAddr in extendedConfigMap.

* Remove "route-http-vserver" & "route-https-vserver" parameters from CIS deployment and define vserverName in extendedConfigMap. CIS will add suffix "_443" for secure virtual server. See Step-2 above.

* Remove "default-client-ssl" & "default-server-ssl" parameters from CIS deployment and define them under "baseRouteSpec" in extendedConfigMap. See Step-2 above.

* Remove "tls-version", "cipher-group" & "ciphers" parameters from CIS deployment and define them under "baseRouteSpec" in extendedConfigMap. See Step-2 above.

* Remove "override-as3-declaration" parameter as it's no more supported with NextGen Routes. You can use the Policy CR to extend the virtual server capabilities. [See Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/Policy).

```
    args: [
      "--bigip-username=admin",
      "--bigip-password=admin",
      "--bigip-url=10.10.10.20",
      "--bigip-partition=openshift",
      "--pool-member-type=cluster",
      "--openshift-sdn-name=/Common/openshift_vxlan",
      "--controller-mode=openshift",
      "--namespace=f5demo",
      "--namespace=f5demo2",
      "--log-level=DEBUG",
      "--log-as3-response=true",
      "--extended-spec-configmap=f5demo2/extended-spec-config",
      "--insecure=true",
      "--route-label=f5type=systest",
      ]
```

