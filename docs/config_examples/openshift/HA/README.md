# Container Ingress Services with BIGIP HA on OpenShift 3.11/4.x - Quick Start Guide 

**Note: This solution applies to BIG-IP devices v13.x and later only.**

## 1. Introduction

This document provides quickstart instructions for installation, configuration and deployment of CIS on OCP 3.11/4.x and integration with BIG-IP in HA.

This guide documents dual CIS with BIGIPs configured in HA. Please open issues on my github page on contact me at m.dittmer@f5.com


## 2. Prerequisite

* OCP: 3.11/4.x - one master and two worker nodes
* CIS: 2.x 
* AS3: 3.18
* 2 BIG-IP 14.1.2.2

CIS uses AS3 declarative API. We need the AS3 extension installed on BIGIP.

From CIS > 2.0, AS3 >= 3.18 is required.
 
* Install AS3 on BIGIP
https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/installation.html

* Get the required YAML files for the repo and update the files to the setup environment.
https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/openshift for YAML files to use moving forward.

## 3. Adding BIG-IP to OpenShift Cluster

### 3.1 Create a new OpenShift HostSubnet

Create one HostSubnet for each BIG-IP device. 
These will handle health monitor traffic. 
Also create one HostSubnet to pass data traffic using floating IP address. 

**Note** Refer YAML files at https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/openshift/HA
Clone, the repo and update appropriately as per the environment.

```
oc create -f f5-kctlr-openshift-hostsubnet-ose-bigip-01.yaml
oc create -f f5-kctlr-openshift-hostsubnet-ose-bigip-02.yaml
oc create -f f5-kctlr-openshift-hostsubnet-float.yaml
```

```
[root@ocp]# oc get hostsubnets
NAME                               HOST                               HOST IP          SUBNET          EGRESS CIDRS   EGRESS IPS
f5-ose-bigip-01                    f5-ose-bigip-01                    192.168.200.82   10.131.0.0/23   []             []
f5-ose-bigip-02                    f5-ose-bigip-02                    192.168.200.83   10.128.2.0/23   []             []
f5-ose-float                       f5-ose-float                       192.168.200.81   10.129.2.0/23   []             []
ose-3-11-master.lab.fp.f5net.com   ose-3-11-master.example.com        192.168.200.84   10.128.0.0/23   []             []
ose-3-11-node1.lab.fp.f5net.com    ose-3-11-node1.example.com         192.168.200.85   10.130.0.0/23   []             []
ose-3-11-node2.lab.fp.f5net.com    ose-3-11-node2.example.com         192.168.200.86   10.129.0.0/23   []             []
```
### 3.2 Create a VXLAN profile

Create a VXLAN profile that uses multi-cast flooding on each BIGIP

```
(tmos)# create net tunnels vxlan openshift_vxlan flooding-type multipoint

```
### 3.3 Create a VXLAN tunnel

Set the key to 0 to grant the BIG-IP device access to all OpenShift projects and subnets

```
on ose-bigip-01 create the VXLAN tunnel
(tmos)# create /net tunnels tunnel openshift_vxlan key 0 profile openshift_vxlan local-address 192.168.200.81 secondary-address 192.168.200.82 traffic-group traffic-group-1
```
```
On ose-bigip-02 create the VXLAN tunnel
(tmos)# create /net tunnels tunnel openshift_vxlan key 0 profile openshift_vxlan local-address 192.168.200.81 secondary-address 192.168.200.83 traffic-group traffic-group-1
```
### 3.4 Create a self IP in the VXLAN

Create a self IP address in the VXLAN on each device. The subnet mask you assign to the self IP must match the one that the OpenShift SDN assigns to nodes. **Note** that is a /14 by default. Be sure to specify a floating traffic group (for example, traffic-group-1). Otherwise, the self IP will use the BIG-IP system’s default

```
[root@ocp]# oc get hostsubnets
NAME                               HOST                               HOST IP          SUBNET          EGRESS CIDRS   EGRESS IPS
f5-ose-bigip-01                    f5-ose-bigip-01                    192.168.200.82   10.131.0.0/23   []             []
f5-ose-bigip-02                    f5-ose-bigip-02                    192.168.200.83   10.128.2.0/23   []             []
f5-ose-float                       f5-ose-float                       192.168.200.81   10.129.2.0/23   []             []
```
On ose-bigip-01 create the self IP
```
(tmos)# create /net self 10.131.0.82/14 allow-service default vlan openshift_vxlan
```
On ose-bigip-02 create the self IP
```
(tmos)# create /net self 10.128.2.83/14 allow-service default vlan openshift_vxlan
```
On the active BIGIP, create a floating IP address in the subnet assigned by the OpenShift SDN
```
(tmos)# create /net self 10.129.2.81/14 allow-service default traffic-group traffic-group-1 vlan openshift_vxlan
```
### 3.5 Create a new partition on your BIG-IP system

Create a new partition on your BIG-IP system
```
(tmos)# create auth partition openshift
```

## 4. Configure and Deploy CIS

### 4.1 Create CIS Controller, BIG-IP credentials and RBAC Authentication

Deploy both ose-bigip-01 and ose-bigip-02 for the associated BIGIPs.

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

**Create Secret `bigip-login` with BIG-IP login credentials. This is used in CIS deployment.**

```
oc create secret generic bigip-login --namespace kube-system --from-literal=username=admin --from-literal=password=f5PME123
```

**Create Service Account**
```
oc create serviceaccount bigip-ctlr -n kube-system
```

**Create Cluster-role and Cluster-role-binging**
```
oc create -f f5-kctlr-openshift-clusterrole.yaml
```

**Create 1 instances of CIS**
```
oc create -f f5-k8s-bigip-ctlr-openshift-ose-bigip-01.yaml
oc create -f f5-k8s-bigip-ctlr-openshift-ose-bigip-02.yaml
```

**Add Cluster role cluster-admin to Service account created above**
``` 
oc adm policy add-cluster-role-to-user cluster-admin -z bigip-ctlr -n kube-system
```

This will deploy and start CIS. Check BIG-IP partition `<partition>_AS3` for L4-L7 info and `<partition>` for L2-L3 info. 

## 5. Sample routes 

Let's create some sample routes. The routes examples in the repo capture most commonly used OpenShift routes that are processed by CIS.

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
oc get pod -n kube-system
oc log  deploy/<CIS-DEPLOYMENT-NAME> -f -n kube-system | grep -i 'as3'
```
## 7. Delete CIS.

### 7.1 Delete kubernetes bigip container connecter, authentication and RBAC
```
oc delete serviceaccount bigip-ctlr -n kube-system
oc delete -f f5-kctlr-openshift-clusterrole.yaml
oc delete -f f5-k8s-bigip-ctlr-openshift-ose-bigip-01.yaml
oc delete -f f5-k8s-bigip-ctlr-openshift-ose-bigip-02.yaml
oc delete secret bigip-login -n kube-system
```
