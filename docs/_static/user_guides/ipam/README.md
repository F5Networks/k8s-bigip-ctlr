# F5 IPAM Controller User Guide

The F5 IPAM Controller is a Docker container that allocates IP addresses from an static list for hostnames. The F5 IPAM Controller watches CRD resources and consumes the hostnames within each resource.

## Prerequisites

* Recommend AS3 version 3.26 [repo](https://github.com/F5Networks/f5-appsvcs-extension/releases/tag/v3.26.0)
* CIS 2.4 [repo](https://github.com/F5Networks/k8s-bigip-ctlr/releases/tag/v2.4.0)
* F5 IPAM Controller [repo](https://github.com/F5Networks/f5-ipam-controller/releases/tag/v0.1.2)
* Github [documentation](https://github.com/F5Networks/f5-ipam-controller#readme)

## Setup Options

CIS 2.4 provides the following options for using the F5 IPAM controller

* Defining the IPAM label in the virtualserver CRD which maps to the IP-Range. In my example I am using the following 

  - ip-range='{"Test":"10.192.75.113-10.192.75.116","Production":"10.192.125.30-10.192.125.50"}'
  - hostname "mysite.f5demo.com" and "myapp.f5demo.com"

* Updating the IP status for the virtualserver CRD

In CIS 2.4 the F5 IPAM Controller can:

* Allocate IP address from static IP address pool based on the CIDR mentioned in a Kubernetes resource

* F5 IPAM Controller decides to allocate the IP from the respective IP address pool for the hostname specified in the virtualserver custom resource

**Note** The idea here is that you specify the ip-range label in the virtualserver CRD, or using Type LB. 

## F5 CIS Configuration Options for IPAM Deployment defining the CIDR network label in the VirtualServer CRD

### Step 1

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
  - "--share-nodes=true"
```

Deploy CIS

```
kubectl create -f f5-cluster-deployment.yaml
```

cis-deployment [repo](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/ipam/cis-deployment/f5-cluster-deployment.yaml)

## F5 IPAM Deploy Configuration Options

### Step 2

* --orchestration=kubernetes

The orchestration parameter holds the orchestration environment i.e. Kubernetes

* --ip-range='{"Test":"10.192.75.113-10.192.75.116","Production":"10.192.125.30-10.192.125.50"}'

ip-range parameter holds the IP address ranges and from this range, it creates a pool of IP address range which gets allocated to the corresponding hostname in the virtual server CRD.

* --log-level=debug

```
- args:
    - --orchestration=kubernetes
    - --ip-range='{"Test":"10.192.75.113-10.192.75.116","Production":"10.192.125.30-10.192.125.50"}'
    - --log-level=DEBUG
```

Deploy RBAC, schema and F5 IPAM Controller deployment

```
kubectl create -f f5-ipam-rbac.yaml
kubectl create -f f5-ipam-schema.yaml
kubectl create -f f5-ipam-deployment.yaml
```
## Logging output when deploying the F5 IPAM Controller

```
[kube@k8s-1-19-master crd-example]$ kubectl logs -f deploy/f5-ipam-controller -n kube-system
Found 2 pods, using pod/f5-ipam-controller-5d76c6f964-n9v6p
2021/04/20 17:10:47 [INFO] [INIT] Starting: F5 IPAM Controller - Version: 0.1.2, BuildInfo: azure-208-24641f25a94eadfef5ebd159315a091280e626a5
2021/04/20 17:10:47 [DEBUG] Creating IPAM Kubernetes Client
2021/04/20 17:10:47 [DEBUG] [ipam] Creating Informers for Namespace kube-system
2021/04/20 17:10:47 [DEBUG] Created New IPAM Client
2021/04/20 17:10:47 [DEBUG] [MGR] Creating Manager with Provider: f5-ip-provider
2021/04/20 17:10:47 [DEBUG] [STORE] [id ipaddress status ipam_label]
2021/04/20 17:10:47 [DEBUG] [STORE]  1   10.192.75.113 1 Test
2021/04/20 17:10:47 [DEBUG] [STORE]  2   10.192.75.114 1 Test
2021/04/20 17:10:47 [INFO] [CORE] Controller started
2021/04/20 17:10:47 [INFO] Starting IPAMClient Informer
2021/04/20 17:10:47 [DEBUG] [STORE]  3   10.192.75.115 1 Test
2021/04/20 17:10:47 [DEBUG] [STORE]  4   10.192.125.30 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  5   10.192.125.31 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  6   10.192.125.32 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  7   10.192.125.33 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  8   10.192.125.34 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  9   10.192.125.35 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  10  10.192.125.36 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  11  10.192.125.37 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  12  10.192.125.38 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  13  10.192.125.39 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  14  10.192.125.40 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  15  10.192.125.41 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  16  10.192.125.42 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  17  10.192.125.43 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  18  10.192.125.44 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  19  10.192.125.45 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  20  10.192.125.46 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  21  10.192.125.47 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  22  10.192.125.48 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  23  10.192.125.49 1 Production
I0420 17:10:47.790510       1 shared_informer.go:240] Waiting for caches to sync for F5 IPAMClient Controller
2021/04/20 17:10:47 [DEBUG] Enqueueing on Create: kube-system/ipam.192.168.200.60.k8s
I0420 17:10:47.903745       1 shared_informer.go:247] Caches are synced for F5 IPAMClient Controller
2021/04/20 17:10:47 [DEBUG] K8S Orchestrator Started
2021/04/20 17:10:47 [DEBUG] Starting Custom Resource Worker
2021/04/20 17:10:47 [DEBUG] Starting Response Worker
2021/04/20 17:10:47 [DEBUG] Processing Key: &{0xc000154160 <nil> Create}
2021/04/20 17:12:35 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.200.60.k8s
2021/04/20 17:12:35 [DEBUG] Processing Key: &{0xc00055a840 0xc000154160 Update}
```

ipam-deployment [repo](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/ipam/crd/big-ip-60-cluster/ipam-deployment/f5-ipam-deployment.yaml)


## Configuring CIS CRD to work with F5 IPAM Controller for the following hosts

- hostname "mysite.f5demo.com"
- hostname "myapp.f5demo.com"

### Step 3

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

crd-example [repo](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/ipam/crd/big-ip-60-cluster/crd-example)

## Logging output when the virtualserver is created

```
2021/04/20 17:12:35 [DEBUG] [CORE] Allocated IP: 10.192.75.113 for Request:
Hostname: mysite.f5demo.com     Key:    CIDR:   IPAMLabel: Test IPAddr:         Operation: Create
2021/04/20 17:12:35 [DEBUG] [PROV] Created 'A' Record. Host:mysite.f5demo.com, IP:10.192.75.113
2021/04/20 17:12:35 [DEBUG] Updated: kube-system/ipam.192.168.200.60.k8s with Status. With IP: 10.192.75.113 for Request:
Hostname: mysite.f5demo.com     Key:    CIDR:   IPAMLabel: Test IPAddr: 10.192.75.113   Operation: Create
2021/04/20 17:13:01 [DEBUG] [CORE] Allocated IP: 10.192.125.30 for Request:
Hostname: myapp.f5demo.com      Key:    CIDR:   IPAMLabel: Production   IPAddr:         Operation: Create
2021/04/20 17:13:01 [DEBUG] [PROV] Created 'A' Record. Host:myapp.f5demo.com, IP:10.192.125.30
2021/04/20 17:13:01 [DEBUG] Updated: kube-system/ipam.192.168.200.60.k8s with Status. With IP: 10.192.125.30 for Request:
Hostname: myapp.f5demo.com      Key:    CIDR:   IPAMLabel: Production   IPAddr: 10.192.125.30   Operation: Create
```

## View the F5 IPAM Controller configuration

F5 IPAM Controller creates the following CRD to create the configuration between CIS and IPAM 

```
[kube@k8s-1-19-master crd-example]$ kubectl describe f5ipam -n kube-system
Name:         ipam.192.168.200.60.k8s
Namespace:    kube-system
Labels:       <none>
Annotations:  <none>
API Version:  fic.f5.com/v1
Kind:         F5IPAM
Metadata:
  Creation Timestamp:  2021-04-19T17:59:38Z
  Generation:          11
  Managed Fields:
    API Version:  fic.f5.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:spec:
    Manager:      k8s-bigip-ctlr
    Operation:    Update
    Time:         2021-04-19T20:15:18Z
    API Version:  fic.f5.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:status:
        .:
        f:IPStatus:
    Manager:      f5-ipam-controller
    Operation:    Update
    Time:         2021-04-20T17:22:41Z
    API Version:  fic.f5.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:spec:
        f:hostSpecs:
    Manager:         k8s-bigip-ctlr.real
    Operation:       Update
    Time:            2021-04-20T17:22:41Z
  Resource Version:  50804197
  Self Link:         /apis/fic.f5.com/v1/namespaces/kube-system/f5ipams/ipam.192.168.200.60.k8s
  UID:               611befc3-63e3-4558-858e-3868adf9bda4
Spec:
  Host Specs:
    Host:        mysite.f5demo.com
    Ipam Label:  Test
    Host:        myapp.f5demo.com
    Ipam Label:  Production
Status:
  IP Status:
    Host:        mysite.f5demo.com
    Ip:          10.192.75.113
    Ipam Label:  Test
    Host:        myapp.f5demo.com
    Ip:          10.192.125.30
    Ipam Label:  Production
Events:          <none>
[kube@k8s-1-19-master crd-example]$
```

View the F5 IPAM CRD and allocate IP status

```
kubectl describe f5ipam -n kube-system
```
