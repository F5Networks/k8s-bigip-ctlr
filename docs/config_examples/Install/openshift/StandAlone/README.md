# OpenShift 3.11/4.x - Container Ingress Services Quick Start Guide with Single BIG-IP 

## 1. Introduction

This document provides quickstart instructions for installation, configuration and deployment of CIS on OCP 3.11/4.x and integration with standalone BIGIP.

## 2. Prerequisite

CIS uses AS3 declarative API. We need the AS3 extension installed on BIGIP. 

From CIS > 2.0, AS3 >= 3.18 is required.
 
* Install AS3 on BIGIP
  https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/installation.html

* Get the required YAML files for the repo and update the files to the setup environment.
  https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/openshift for YAML files to use moving forward.

## 3. Adding BIG-IP to OpenShift Cluster

### 3.1 Create a new OpenShift HostSubnet

Create a host subnet for the BIPIP. This will provide the subnet for creating the tunnel self-IP.

```
oc create -f f5-kctlr-openshift-hostsubnet.yaml
```
```
[root@ose-3-11-master openshift-3-11]# oc get hostsubnets
NAME                               HOST                               HOST IP          SUBNET          EGRESS CIDRS   EGRESS IPS
f5-server                          f5-server                          192.168.200.83   10.131.0.0/23   []     []
ose-3-11-master.example.com        ose-3-11-master.example.com        192.168.200.84   10.128.0.0/23   []     []
ose-3-11-node1.example.com         ose-3-11-node1.example.com         192.168.200.85   10.130.0.0/23   []     []
ose-3-11-node2.lexample.com        ose-3-11-node2.example.com         192.168.200.86   10.129.0.0/23   []     []
```
### 3.2 Create a BIG-IP VXLAN tunnel

#### create net tunnels vxlan vxlan-mp flooding-type multipoint
```
(tmos)# create net tunnels vxlan vxlan-mp flooding-type multipoint
(tmos)# create net tunnels tunnel openshift_vxlan key 0 profile vxlan-mp local-address 192.168.200.83
```
### 3.3 Add the BIG-IP device to the OpenShift overlay network
```
(tmos)# create net self 10.131.0.83/14 allow-service all vlan openshift_vxlan
```
Subnet comes from the creating the hostsubnets. Used .83 to be consistent with BigIP internal interface

### 3.4 Create a new partition on your BIG-IP system
```
(tmos)# create auth partition openshift
```
This needs to match the partition in the CIS configuration

## 4. Configure and Deploy CIS Controller

### 4.1  Create CIS Controller, BIG-IP credentials and RBAC Authentication

```
args: [
        "--bigip-username=$(BIGIP_USERNAME)",
        "--bigip-password=$(BIGIP_PASSWORD)",
        # Replace with the IP address or hostname of your BIG-IP device
        "--bigip-url=<BIGIP_ADDRESS>",
        # Replace with the name of the BIG-IP partition you want to manage
        "--bigip-partition=<PARTITION_CREATED_ABOVE>",
        "--pool-member-type=<cluster|nodeport>",
        # Replace with the path to the BIG-IP VXLAN connected to the
        # OpenShift HostSubnet
        "--openshift-sdn-name=<HOST_SUBNET>",
        "--manage-routes=true",
        "--namespace=f5demo",
        "--route-vserver-addr=<VS_IP_ADDRESS>",
        "--log-level=DEBUG",
        # Self-signed cert
        "--insecure=true",
       ]
```
```
oc create secret generic bigip-login --namespace kube-system --from-literal=username=admin --from-literal=password=f5PME123
oc create serviceaccount bigip-ctlr -n kube-system
oc create -f f5-kctlr-openshift-clusterrole.yaml
oc create -f f5-k8s-bigip-ctlr-openshift.yaml
oc adm policy add-cluster-role-to-user cluster-admin -z bigip-ctlr -n kube-system
```

This will deploy and start CIS. Check BIG-IP partition `<partition>_AS3` for L4-L7 info and `<partition>` for L2-L3 info. 

## 5. Sample routes 

Let's create some sample routes. The routes examples in the repo capture most commonly used OpenShift routes that are processed by CIS.

Update sample routes specifications with appropriate certificates/keys and BIG-IP objects.

### 5.1 Create example routes
```
oc create -f sample-route-deployment.yaml -n f5demo
oc create -f sample-route-service.yaml -n f5demo
oc create -f sample-edge-route.yaml -n f5demo
oc create -f sample-passthrough-route.yaml -n f5demo
oc create -f sample-reencrypt-route.yaml -n f5demo
oc create -f sample-route-ab.yaml -n f5demo
oc create -f sample-route-balance.yaml -n f5demo
oc create -f sample-route-basic.yaml -n f5demo
oc create -f sample-route-edge-ssl-waf.yaml -n f5demo
oc create -f sample-route-waf.yaml -n f5demo
oc create -f sample-unsecured-route.yaml -n f5demo
```

### 5.2 Delete example routes

```
oc delete -f sample-route-deployment.yaml -n f5demo
oc delete -f sample-route-service.yaml -n f5demo
oc delete -f sample-edge-route.yaml -n f5demo
oc delete -f sample-passthrough-route.yaml -n f5demo
oc delete -f sample-reencrypt-route.yaml -n f5demo
oc delete -f sample-route-ab.yaml -n f5demo
oc delete -f sample-route-balance.yaml -n f5demo
oc delete -f sample-route-basic.yaml -n f5demo
oc delete -f sample-route-edge-ssl-waf.yaml -n f5demo
oc delete -f sample-route-waf.yaml -n f5demo
oc delete -f sample-unsecured-route.yaml -n f5demo

``` 

## 6. Enable logging for AS3

```
oc get deploy -n kube-system
oc log  deploy/<CIS-DEPLOYMENT-NAME> -f -n kube-system | grep -i 'as3'
```

## 7. Delete CIS.

### 7.1 Delete kubernetes bigip container connecter, authentication and RBAC
```
oc delete serviceaccount bigip-ctlr -n kube-system
oc delete -f f5-kctlr-openshift-clusterrole.yaml
oc delete -f f5-k8s-bigip-ctlr-openshift.yaml
oc delete secret bigip-login -n kube-system
```
