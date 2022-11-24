# Migrating to NextGen Routes(**For Preview Release only**)

### Contents

[Overview](#overview)

[Prerequisites](#prerequisites)

[Deprecated Annotations](#deprecated-annotations)

[Example Migration to nextGen Routes](#example-migration-to-nextgen-routes)


## Overview
NextGenRoute Controller uses extendedConfigMap for extending the native resources (routes). All the routes are group by namespaces or namespace-labels into RouteGroups. Each RouteGroup shares the same vsAddress, vsName and policy CR  which is specified in extendedConfigMap. 
In order to migrate to nextGen we first need to create an extended ConfigMap and policy CR then modify the CIS deployment accordingly. Refer `NextGen Route Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details

## Prerequisites
Stop the running CIS.

## Deprecated Annotations

* "virtual-server.f5.com/allow-source-range" or "virtual-server.f5.com/whitelist-source-range" annotation is deprecate, you can define the allow-source-range in Policy CR. See Step-3 below.
* "virtual-server.f5.com/waf" - This annotation is deprecate, you can define the waf in Policy CR. See Step-3 below.

**Note**: You can still keep the annotations in your routes. CIS will simply ignore to process these annotations.

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
    kubectl create -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml
    ```

#### Step-2 Grouping the routes using Namespace labels
* If CIS is watching all the namespaces or specific namespaces, customer/user needs to introduce the namespace-label parameter in CIS deployment and tag all the monitored namespaces with namespace-label. See Step-5.
* If CIS is watching namespaces using namespaceLabel, then no additional changes required in CIS deployment.

You can use following command to add the label to a namespace

    ```
    oc label namespaces f5demo cis=true 
    oc label namespaces f5demo2 cis=true
    ```
    
#### Step-3 Creating Extended ConfigMap

Extended ConfigMap is a must to use the nextGen Route Controller. Refer `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details          

You can create an extended ConfigMap for given example as follows:
* You can define the vserverAddr same as "route-vserver-addr" parameter in CIS deployment.
* Use the namespace label created in step-2 to group the routes

    ```
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: global-spec-config
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
          extendedRouteSpec:
          - namespaceLabel: cis=true
            vserverAddr: 10.192.75.107
            vserverName: test_vs
            policyCR: f5demo2/sample-policy
    ```
  
**Note**: Make sure the namespace where we created the ConfigMap monitored by CIS.

#### Step-4: Prepare the Policy CR 
You can create the Policy CR as follows for WAF and AllowSourceRange annotations:

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
    * You can use the Policy CR to extend the virtual server capabilities even more. [See Details](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/Policy).
    * Make sure the namespace where we created the policy CR monitored by CIS.   
 
#### Step-5 Update the CIS deployment parameters and start
* Configure --controller-mode: openshift to use NextGen Route controller in CIS.

    ```
        - --controller-mode
        - openshift
    ```

* Configure extended ConfigMap and specify that in the CIS deployment parameter.
    
    ```
        - --route-spec-configmap
        - f5demo2/global-spec-config
    ```

* If CIS is watching all the namespaces or specific namespaces, customer needs to introduce the namespace-label parameter in CIS deployment and tag all the monitored namespaces with namespace-label. See Step-2 above.

    ```
        - --namespace-label=cis=true
    ```  

* Remove "route-vserver-addr" parameter from CIS deployment and define as vserverAddr in extendedConfigMap.

* Remove "route-http-vserver" & "route-https-vserver" parameters from CIS deployment and define vserverName in extendedConfigMap. CIS will add suffix "_443" for secure virtual server. See Step-2 below.

* Remove "default-client-ssl" & "default-server-ssl" parameters from CIS deployment and define them under "baseRouteSpec" in extendedConfigMap. See Step-2 below.

* Remove "tls-version", "cipher-group" & "ciphers" parameters from CIS deployment and define them under "baseRouteSpec" in extendedConfigMap. See Step-2 below.

* Remove "override-as3-declaration" parameter as it's no more supported with NextGen Routes. You can use the Policy CR to extend the virtual server capabilities. [See Example](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/Policy).

    ```
                args: [
                  "--bigip-username=admin",
                  "--bigip-password=admin",
                  "--bigip-url=10.10.10.20",
                  "--bigip-partition=openshift",
                  "--pool-member-type=cluster",
                  "--openshift-sdn-name=/Common/openshift_vxlan",
                  "--controller-mode=openshift",
                  "--namespace-label=cis=true",
                  "--log-level=DEBUG",
                  "--log-as3-response=true",
                  "--route-spec-configmap=f5demo2/global-spec-config",
                  "--insecure=true",
                  "--route-label=f5type=systest",
                  ]
    ```

