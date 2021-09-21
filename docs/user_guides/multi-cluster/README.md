# Multi-Cluster Kubernetes using Container Ingress Services (CIS) and BIG-IP using Flannel

Today, organizations are increasingly deploying multiple Kubernetes clusters. Deploying multiple Kubernetes clusters can improve availability, isolation and scalability. This user-guide documents how CIS can automate BIP-IP to provide Edge Ingress services for a dev to prod Kubernetes cluster.

## Multi-Cluster Application Architecture

In this user-guide, each cluster runs a full copy of the application. This simple but powerful approach enables an application to be graduated from dev to prod. Future user-guides will focus on multiple availability zones using health-aware global load balancing. Diagram below represents the two clusters in the user-guide. 

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/diagrams/2021-05-10_12-07-00.png)

Demo on YouTube [video](https://youtu.be/VimGK5PPViE)

### Environment parameters

* Two clusters - one master and two worker nodes running version 1.21
* Recommend AS3 version 3.26 [repo](https://github.com/F5Networks/f5-appsvcs-extension/releases/tag/v3.26.0)
* CIS 2.4 [repo](https://github.com/F5Networks/k8s-bigip-ctlr/releases/tag/v2.4.0)
* F5 IPAM Controller [repo](https://github.com/F5Networks/f5-ipam-controller/releases/tag/v0.1.2)
* CloudDocs [documentation](https://clouddocs.f5.com/containers/latest/userguide/kubernetes/)

## Kubernetes Flannel Modification

Changes are required to flannel networking in both the Kubernetes cluster and BIG-IP. These changes are mostly required to the prod-cluster. Assuming that you have installed a fresh Kubernetes cluster via kubeadm builder tool with adopting appropriate --pod-network-cidr flag in kubeadm init command shown below:

```
kubeadm init --apiserver-advertise-address=192.168.200.70 --pod-network-cidr=10.244.0.0/16
kubeadm init --apiserver-advertise-address=192.168.200.80 --pod-network-cidr=10.245.0.0/16
```

**Note:** A workaround is to edit the prod-cluster ConfigMap file of flannel, kube-flannel-cfg and to replace with the new Network value. By default kubeadm uses "Network": "10.244.0.0/16". Replace and add the "Network", "VNI" fields under net-conf.json header in the relevant Flannel ConfigMap with a new network IP range. After modification a reboot of the cluster is required.

    $ kubectl edit cm kube-flannel-cfg -n kube-system

```
net - conf.json: | {
	"Network": "10.245.0.0/16",
	"Backend": {
		"Type": "vxlan",
		"VNI": 11
	}
}
```
Output should look like the example below for the prod-cluster

```
[kube@ks8-prod-master pod-deployment]$ cat /run/flannel/subnet.env
FLANNEL_NETWORK=10.245.0.0/16
FLANNEL_SUBNET=10.245.0.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=true
```
Changes are also required to all the backend-data annotations of the Kubenetes nodes in the prod-cluster. This includes the big-ip-node documented below

    $ kubectl edit nodes

```
annotations:
      flannel.alpha.coreos.com/backend-data: '{"VNI":11,"VtepMAC":"ae:0b:f0:f4:fc:1a"}'
      flannel.alpha.coreos.com/backend-type: vxlan
      flannel.alpha.coreos.com/kube-subnet-manager: "true"
      flannel.alpha.coreos.com/public-ip: 192.168.200.80
```

## BIG-IP Vxlan Tunnels and Self-IPs Setup

**Note:** Multi-cluster requires that the vxlan tunnels and self-IPs are created in a unique tenant. In this example i have create two tenant names dev and prod. Creating the vxlan tunnels and self-IPs in the /Common tenant wont work.

### Create vxlan tunnels and self-IPs for the dev cluster

* create net tunnels vxlan fl-vxlan port 8472 flooding-type none
* create net tunnel tunnel vxlan-tunnel-dev key 1 profile fl-vxlan local-address 192.168.200.60
* create net self 10.244.20.60 address 10.244.20.60/255.255.0.0 allow-service none vlan vxlan-tunnel-dev

### Create vxlan tunnels and self-IPs for the prod cluster

* create net tunnel tunnel vxlan-tunnel-prod key 11 profile fl-vxlan local-address 192.168.200.60
* create net self 10.245.20.60 address 10.245.20.60/255.255.0.0 allow-service none vlan vxlan-tunnel-prod

### Example of vxlan tunnels and Self-IPs for the vxlan-tunnel-dev

Tunnel profile fl-vxlan configuration for vxlan-tunnel-dev

![vxlan-tunnel](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/diagrams/2021-05-10_12-11-17.png)

Self-IPs configuration for vxlan-tunnel-dev

![self-ip](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/diagrams/2021-05-10_12-28-33.png)

### Example of vxlan tunnels and Self-IPs for the vxlan-tunnel-prod

Tunnel profile fl-vxlan configuration for vxlan-tunnel-prod

![vxlan-tunnel](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/diagrams/2021-05-10_12-11-53.png)

Self-IPs configuration for vxlan-tunnel-prod

![self-ip](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/diagrams/2021-05-10_12-27-39.png)

### Create BIG-IP Node required Tunnel: vxlan-tunnel-dev and vxlan-tunnel-prod

Find the VTEP MAC address for tunnels vxlan-tunnel-dev and vxlan-tunnel-prod.

```
(tmos)# show net tunnels tunnel vxlan-tunnel-dev all-properties

-------------------------------------------------
Net::Tunnel: vxlan-tunnel-dev
-------------------------------------------------
MAC Address                     00:50:56:bb:32:66
Interface Name                    vxlan-tunnel-~1

Incoming Discard Packets                        0
Incoming Error Packets                          0
Incoming Unknown Proto Packets                  0
Outgoing Discard Packets                        0
Outgoing Error Packets                         10
HC Incoming Octets                              0
HC Incoming Unicast Packets                     0
HC Incoming Multicast Packets                   0
HC Incoming Broadcast Packets                   0
HC Outgoing Octets                              0
HC Outgoing Unicast Packets                     0
HC Outgoing Multicast Packets                   0
HC Outgoing Broadcast Packets                   0
```

```
tmos)# show net tunnels tunnel vxlan-tunnel-prod all-properties

-------------------------------------------------
Net::Tunnel: vxlan-tunnel-prod
-------------------------------------------------
MAC Address                     00:50:56:bb:32:66
Interface Name                    vxlan-tunnel-~2

Incoming Discard Packets                        0
Incoming Error Packets                          0
Incoming Unknown Proto Packets                  0
Outgoing Discard Packets                        0
Outgoing Error Packets                         10
HC Incoming Octets                              0
HC Incoming Unicast Packets                     0
HC Incoming Multicast Packets                   0
HC Incoming Broadcast Packets                   0
HC Outgoing Octets                              0
HC Outgoing Unicast Packets                     0
HC Outgoing Multicast Packets                   0
HC Outgoing Broadcast Packets                   0
```

### Create two “dummy” Kubernetes Node for Tunnel: vxlan-tunnel-dev and vxlan-tunnel-prod

Include all of the flannel Annotations. Define the backend-data and public-ip Annotations with data from the BIG-IP VXLAN:

**vxlan-tunnel-dev**
```
apiVersion: v1
kind: Node
metadata:
  name: vxlan-tunnel-dev
  annotations:
    #Replace MAC with your BIGIP Flannel VXLAN Tunnel MAC
    flannel.alpha.coreos.com/backend-data: '{"VtepMAC":"00:50:56:bb:32:66"}'
    flannel.alpha.coreos.com/backend-type: "vxlan"
    flannel.alpha.coreos.com/kube-subnet-manager: "true"
    #Replace IP with Self-IP for your deployment
    flannel.alpha.coreos.com/public-ip: "192.168.200.60"
spec:
  #Replace Subnet with your BIGIP Flannel Subnet
  podCIDR: "10.244.20.0/24
```

**vxlan-tunnel-prod**
```
apiVersion: v1
kind: Node
metadata:
  name: vxlan-tunnel-prod
  annotations:
    #Replace MAC with your BIGIP Flannel VXLAN Tunnel MAC
    flannel.alpha.coreos.com/backend-data: '{"VNI":11,"VtepMAC":"00:50:56:bb:32:66"}'
    flannel.alpha.coreos.com/backend-type: "vxlan"
    flannel.alpha.coreos.com/kube-subnet-manager: "true"
    #Replace IP with Self-IP for your deployment
    flannel.alpha.coreos.com/public-ip: "192.168.200.60"
spec:
  #Replace Subnet with your BIGIP Flannel Subnet
  podCIDR: "10.245.20.0/24"
```

dev-cluster
* f5-bigip-dev-node.yaml [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/dev-cluster/cis/cis-deployment/f5-bigip-dev-node.yaml)

prod-cluster
* f5-bigip-prod-node.yaml [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/prod-cluster/cis/cis-deployment/f5-bigip-prod-node.yaml)


## Deploy CIS for each BIG-IP for dev-cluster and prod-cluster

Configuration options available in the CIS controller for the dev-cluster
```
    spec: 
      containers: 
        - 
          args: 
            - "--bigip-username=$(BIGIP_USERNAME)"
            - "--bigip-password=$(BIGIP_PASSWORD)"
            - "--bigip-url=192.168.200.60"
            - "--bigip-partition=dev"
            - "--namespace=dev"
            - "--pool-member-type=cluster"
            - "--flannel-name=/dev/vxlan-tunnel-dev"
            - "--log-level=DEBUG"
            - "--insecure=true"
            - "--log-as3-response=true"
            - "--custom-resource-mode=true"
            - "--ipam=true"
            - "--as3-post-delay=30"
```

Configuration options available in the CIS controller for the prod-cluster
```
    spec: 
      containers: 
        - 
          args: 
            - "--bigip-username=$(BIGIP_USERNAME)"
            - "--bigip-password=$(BIGIP_PASSWORD)"
            - "--bigip-url=192.168.200.60"
            - "--bigip-partition=prod"
            - "--namespace=prod"
            - "--pool-member-type=cluster"
            - "--flannel-name=/prod/vxlan-tunnel-prod"
            - "--log-level=DEBUG"
            - "--insecure=true"
            - "--log-as3-response=true"
            - "--custom-resource-mode=true"
            - "--ipam=true"
            - "--as3-post-delay=30"
```

dev-cluster
* f5-cis-deployment.yaml [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/dev-cluster/cis/cis-deployment/f5-cis-deployment.yaml)

prod-cluster
* f5-cis-deployment.yaml [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/prod-cluster/cis/cis-deployment/f5-cis-deployment.yaml)

## CIS Configuration Options using IPAM for the Dev and Prod Cluster

CIS 2.4 introduces IPAM which provides IP management for the different clusters. Using CIS + IPAM will simplify the configuration of the CRD VirtualServer. The devops user only need to define a ipamlabel in the CRD and IPAM will provide a public IP for the specific hostname. 

* Defining the ip-range for the **dev network** and **dev ipamlabel** in the IPAM deployment manifest
    - --ip-range='{"dev":"10.192.75.113-10.192.75.116"}'

* Defining the ip-range for the **prod network** and **dev ipamlabel** in the IPAM deployment manifest
    - --ip-range='{"prod":"10.192.125.30-10.192.125.50"}'

Deploy RBAC, schema and F5 IPAM Controller deployment for both the dev and prod cluster

```
kubectl create -f f5-ipam-rbac.yaml
kubectl create -f f5-ipam-schema.yaml
kubectl create -f f5-ipam-deployment.yaml
```

dev-cluster
* f5-ipam-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/dev-cluster/ipam/f5-ipam-deployment.yaml)

prod-cluster
* f5-cis-deployment.yaml [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/multi-cluster/prod-cluster/ipam/f5-ipam-deployment.yaml)

## Configuring CIS CRD for the Dev Cluster based on the Hostname

- hostname "dev.f5demo.com"

Dev user only needs to specify the **ipamLabel: dev** and **host: dev.f5demo.com** is the CRD

```
apiVersion: "cis.f5.com/v1"
kind: VirtualServer
metadata:
  name: f5-demo-dev
  namespace: dev
  labels:
    f5cr: "true"
spec:
  host: dev.f5demo.com
  ipamLabel: dev
  pools:
  - monitor:
      interval: 20
      recv: ""
      send: /
      timeout: 31
      type: http
    path: /
    service: f5-demo-dev
    servicePort: 80
```

### Deploy the CRD and CRD schema

```
kubectl create -f customresourcedefinitions.yaml
kubectl create -f vs-dev.yaml
```

crd-resource [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/multi-cluster/dev-cluster/cis/crd-resource)

## Configuring CIS CRD for the Prod Cluster based on the Hostname

- hostname "prod.f5demo.com"

Dev user only needs to specify the **ipamLabel: prod** and **host: prod.f5demo.com** is the CRD

```
apiVersion: "cis.f5.com/v1"
kind: VirtualServer
metadata:
  name: f5-demo-prod
  namespace: prod
  labels:
    f5cr: "true"
spec:
  host: prod.f5demo.com
  ipamLabel: prod
  pools:
  - monitor:
      interval: 20
      recv: ""
      send: /
      timeout: 31
      type: http
    path: /
    service: f5-demo-prod
    servicePort: 80
```

### Deploy the CRD and CRD schema

```
kubectl create -f customresourcedefinitions.yaml
kubectl create -f vs-prod.yaml
```

crd-resource [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/multi-cluster/prod-cluster/cis/crd-resource)

**Note** For more information on F5 CIS and IPAM please review my user-guide and demo at [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/ipam/README.md)

## Best Practices when using Multiple Kubernetes Clusters and CIS

API scaling is required when using multiple instances of CIS connecting to a single BIG-IP device. In this user-guide, two Kubernetes clusters are targeting a single BIG-IP device. This solution is to modify the settings on both the BIG-IP and CIS to reduce the risk of AS3 errors related to API connections. 

CIS uses the AS3 API to configure BIG-IP. The challenge is if multiple AS3 declaration declare a configuration simultaneously or if the API is busy, CIS could receive a 503 response. If you start to see this error message stating **“Error: Configuration operation in progress on device, please try again in 2 minutes.”**, CIS needs to implement API POST delays.

### Recommended Settings

The following are the recommended configuration to implement API POST delays:

```
          args: 
            - "--bigip-username=$(BIGIP_USERNAME)"
            - "--bigip-password=$(BIGIP_PASSWORD)"
            - "--bigip-url=192.168.200.60"
            - "--bigip-partition=dev"
            - "--namespace=dev"
            - "--pool-member-type=cluster"
            - "--flannel-name=/dev/vxlan-tunnel-dev"
            - "--log-level=DEBUG"
            - "--insecure=true"
            - "--log-as3-response=true"
            - "--custom-resource-mode=true"
            - "--ipam=true"
            - "--as3-post-delay=30"
```

The "as3-post-delay" value changes the behavior of the controller to wait for 30 seconds before making a change. This can queue up changes and perform them as a single update instead of multiple. The --as3-post-delay=30 can be customized for the Kubernetes cluster. In this example i am using 30 seconds.



