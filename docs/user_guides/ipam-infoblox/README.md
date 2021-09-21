# F5 IPAM Controller and F5 Container Ingress Services (CIS) using Infoblox IPAM Integration 

**Please note: Infoblox IPAM Integration with F5 IPAM Controller is in preview**

The F5 IPAM Controller is deployed in Kubernetes working with CIS to allocates IP addresses from Infoblox network ranges. The F5 IPAM Controller watches orchestration-specific CRD resources and consumes the hostnames within each resource. The F5 IPAM Controller integrates with Infoblox WAPI via the RESTful web API to allowcate the virtual server IP addresses as shown below in the diagram.

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/ipam-infoblox/diagram/2021-07-13_13-46-41.png)

Demo on YouTube [video](https://youtu.be/Z7fLfiaMAdc)

## Prerequisites

* Recommend AS3 version 3.29 [repo](https://github.com/F5Networks/f5-appsvcs-extension/releases/tag/v3.29.0)
* CIS 2.5 [repo](https://github.com/F5Networks/k8s-bigip-ctlr/releases/tag/v2.5.0)
* F5 IPAM Controller [repo](https://github.com/F5Networks/f5-ipam-controller/releases/tag/v0.1.2)
* Github [documentation](https://github.com/F5Networks/f5-ipam-controller#readme)
* Infoblox [documentation](https://www.infoblox.com/products/ipam-dhcp/)

## Setup Options

CIS 2.5 provides two deployment option for using the F5 IPAM controller. You can only use one deployment method per F5 IPAM Controller

* ip-range - statically specifies the pool of IP address range based on a ipam label
* infoblox-labels - infoblox labels holds the mappings for infoblox's netView, dnsView and CIDR

In this user-guide we are using the deployment options of Infoblox. In CIS 2.5 the F5 IPAM Controller for Infoblox can:

* Allocate IP address from infoblox data management IP address pool based on the **ipamLabel** in the Kubernetes CRD
* F5 IPAM Controller decides to allocate the IP from the respective IP address pool for the hostname specified in the virtualserver custom resource

**Note** The idea here is that you specify the ip-range label in the virtualserver CRD, or using Type LB. 

## Step 1: CIS Configuration Options for IPAM Deployment defining the CIDR network label in the VirtualServer CRD

Add the parameter --ipam=true in the CIS deployment to provide the integration with CIS and IPAM

* --ipam=true

```
args: 
  - "--bigip-username=$(BIGIP_USERNAME)"
  - "--bigip-password=$(BIGIP_PASSWORD)"
  - "--bigip-url=192.168.200.60"
  - "--bigip-partition=k8s"
  - "--namespace=default"
  - "--pool-member-type=cluster"
  - "--flannel-name=fl-vxlan"
  - "--log-level=DEBUG"
  - "--insecure=true"
  - "--custom-resource-mode=true"
  - "--as3-validation=true"
  - "--log-as3-response=true"
  - "--ipam=true"
```

Deploy CIS

```
kubectl create -f f5-cluster-deployment.yaml
```

cis-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/ipam-infoblox/cis-deployment/f5-cluster-deployment.yaml)

## Step 2: F5 IPAM Deploy Configuration Options

Add the parameter

* --orchestration=kubernetes - The orchestration parameter holds the orchestration environment i.e. Kubernetes
* --infoblox-labels='{"Test":{"cidr": "10.192.75.112/30","netView": "test", "dnsview": "default.test"},"Production":{"cidr": "10.192.125.32/28","netView": "production", "dnsview": "default.production"}}' - ipamlabel ranges and from this Infoblox
* --log-level=debug - recommend info after testing
* --infoblox-grid-host for the URL (or IP Address) of Infoblox Grid Host
* --infoblox-wapi-port the Infoblox Server listens on
* --infoblox-wapi-version API version of Infoblox
* --infoblox username and password

```
args:
  - --orchestration=kubernetes
  - --log-level=DEBUG
  - --ipam-provider=infoblox
  - --infoblox-labels='{"Test":{"cidr": "10.192.75.112/30","netView": "test", "dnsview": "default.test"},"Production":{"cidr": "10.192.125.32/28","netView": "production", "dnsview": "default.production"}}'
  - --infoblox-grid-host=10.192.75.240
  - --infoblox-wapi-port="443"
  - --infoblox-wapi-version=2.10.5
  - --infoblox-username=admin
  - --infoblox-password=infoblox
```

Deploy RBAC, schema and F5 IPAM Controller deployment

```
kubectl create -f f5-ipam-ctlr-clusterrole.yaml
kubectl create -f f5-ipam-schema.yaml
kubectl create -f f5-ipam-deployment.yaml
```
ipam-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/ipam-infoblox/ipam-deployment)

## Logging output when deploying the F5 IPAM Controller

```
$ kubectl logs -f deploy/f5-ipam-controller -n kube-system
[kube@k8s-1-19-master xianfei]$ kubectl logs -f deploy/f5-ipam-controller -n kube-system
2021/07/13 17:39:39 [INFO] [INIT] Starting: F5 IPAM Controller - Version: 0.1.5-WIP, BuildInfo: amkgupta-0382461-dirty-20210712172739
2021/07/13 17:39:39 [DEBUG] Creating IPAM Kubernetes Client
2021/07/13 17:39:39 [DEBUG] [ipam] Creating Informers for Namespace kube-system
2021/07/13 17:39:39 [DEBUG] Created New IPAM Client
2021/07/13 17:39:39 [DEBUG] [MGR] Creating Manager with Provider: infoblox
2021/07/13 17:39:40 [INFO] [CORE] Controller started
2021/07/13 17:39:40 [INFO] Starting IPAMClient Informer
I0713 17:39:40.221163       1 shared_informer.go:240] Waiting for caches to sync for F5 IPAMClient Controller
2021/07/13 17:39:40 [DEBUG] Enqueueing on Create: kube-system/ipam.192.168.200.60.k8s
I0713 17:39:40.322244       1 shared_informer.go:247] Caches are synced for F5 IPAMClient Controller
2021/07/13 17:39:40 [DEBUG] K8S Orchestrator Started
2021/07/13 17:39:40 [DEBUG] Starting Custom Resource Worker
2021/07/13 17:39:40 [DEBUG] Starting Response Worker
```

## Step 3: Configuring CRD to work with F5 IPAM Controller for the following hosts

- hostname "mysite.f5demo.com"
- hostname "myapp.f5demo.com"

Provide a ipamLabel in the virtual server CRD. Make your to create latest CIS virtualserver schema which supports ipamLabel

```
apiVersion: "cis.f5.com/v1"
kind: VirtualServer
metadata:
  name: f5-demo-myapp
  labels:
    f5cr: "true"
spec:
  host: myapp.f5demo.com
  ipamLabel: Production
  pools:
  - monitor:
      interval: 20
      recv: ""
      send: /
      timeout: 31
      type: http
    path: /
    service: f5-demo
    servicePort: 80
```

and

```
apiVersion: "cis.f5.com/v1"
kind: VirtualServer
metadata:
  name: f5-demo-mysite
  labels:
    f5cr: "true"
spec:
  host: mysite.f5demo.com
  ipamLabel: Test
  pools:
  - monitor:
      interval: 20
      recv: ""
      send: /
      timeout: 31
      type: http
    path: /
    service: f5-demo
    servicePort: 80
```

Deploy the CRD and updated schema

```
kubectl create -f customresourcedefinitions.yaml
kubectl create -f vs-mysite.yaml
kubectl create -f vs-myapp.yaml
```

crd-example [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/ipam-infoblox/crd-example)

## Logging output from the VirtualServer

**myapp.f5demo.com**

```
2021/07/13 17:52:21 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.200.60.k8s
2021/07/13 17:52:21 [DEBUG] Processing Key: &{0xc0001e6160 0xc0001e7ce0 Update}
Hostname: myapp.f5demo.com      Key:    CIDR: 10.192.125.32/28  IPAMLabel: Production   IPAddr:         Operation: Create
2021/07/13 17:52:21 [DEBUG] [CORE] Allocated IP: 10.192.125.33 for Request:
Hostname: myapp.f5demo.com      Key:    CIDR:   IPAMLabel: Production   IPAddr:         Operation: Create
2021/07/13 17:52:21 [DEBUG] Updated: kube-system/ipam.192.168.200.60.k8s with Status. With IP: 10.192.125.33 for Request:
Hostname: myapp.f5demo.com      Key:    CIDR:   IPAMLabel: Production   IPAddr: 10.192.125.33   Operation: Create
```
ipamLabel: Production Infoblox setup

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/ipam-infoblox/diagram/2021-07-13_12-58-46.png)

ipam status for CRD 

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/ipam-infoblox/diagram/2021-07-13_13-30-21.png)

**mysite.f5demo.com**

```
2021/07/13 17:41:06 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.200.60.k8s
2021/07/13 17:41:06 [DEBUG] Processing Key: &{0xc0001e7080 0xc000195340 Update}
Hostname: mysite.f5demo.com     Key:    CIDR: 10.192.75.112/30  IPAMLabel: Test IPAddr:         Operation: Create
2021/07/13 17:41:07 [DEBUG] [CORE] Allocated IP: 10.192.75.113 for Request:
Hostname: mysite.f5demo.com     Key:    CIDR:   IPAMLabel: Test IPAddr:         Operation: Create
2021/07/13 17:41:07 [DEBUG] Updated: kube-system/ipam.192.168.200.60.k8s with Status. With IP: 10.192.75.113 for Request:
Hostname: mysite.f5demo.com     Key:    CIDR:   IPAMLabel: Test IPAddr: 10.192.75.113   Operation: Create
```
ipamLabel: Test Infoblox setup

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/ipam-infoblox/diagram/2021-07-13_13-27-21.png)

ipam status for CRD 

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/ipam-infoblox/diagram/2021-07-13_13-33-27.png)


