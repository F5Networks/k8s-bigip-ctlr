# Container Ingress Services using Virtual Server Custom Resource 

This page is created to document the behaviour of CIS in CRD Mode(ALPHA Release). This is an ALPHA release which supports limited features. Check for the Supported Features and TO BE Implemented sections to understand in detail about the features.  

## What are CRDs? 

* Custom resources are extensions of the Kubernetes API. 
* A resource is an endpoint in the Kubernetes API that stores a collection of API objects of a certain kind; for example, the built-in pods resource contains a collection of Pod objects.
* A custom resource is an extension of the Kubernetes API that is not necessarily available in a default Kubernetes installation. It represents a customization of a particular Kubernetes installation. However, many core Kubernetes functions are now built using custom resources, making Kubernetes more modular.
*  Custom resources can appear and disappear in a running cluster through dynamic registration, and cluster admins can update custom resources independently of the cluster itself. Once a custom resource is installed, users can create and access its objects using kubectl, just as they do for built-in resources like Pods.

## How CIS works with CRDs

* CIS registers to the kubernetes client-go using informers to retrieve Virtual Server, Service, Endpoint and Node creation, updation and deletion events. Resources identified from such events
will be pushed to a Resource Queue maintained by CIS.
* Resource Queue holds the resources to be processed.
* Virtual Server is the Primary citizen. Any changes in Service, Endpoint, Node will indirectly affect Virtual Server.
* Worker fetches the affected Virtual Servers from Resource Queue to populate a common structure which holds the configuration of all the Virtual Servers such as Virtual Server IP, Pool Members and L7 LTM policy actions.
* Vxlan Manager prepares the BIG-IP NET configuration as AS3 cannot process FDB and ARP entries.
* LTM Configuration(using AS3) and NET Configuration(using CCCL) will be created in CIS Managed Partition defined by the User.

## Alpha Release
**Supported Features**

* Supports Custom Resource type: VirtualServer.
* Responds to changes in VirtualServer resources.
* Responds to changes in Services and Endpoints.
* Creates a common partition in BIG-IP for both LTM and NET objects.

**To Be Implemented**

* TLS support for Virtual Server Custom Resource.

## Prerequisites
Since CIS is using the AS3 declarative API we need the AS3 extension installed on BIG-IP. Follow the link to install AS3 3.18 is required for CIS 2.0.
 
* Install AS3 on BIG-IP - https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/installation.html

## Installation
**Create CIS Controller, BIG-IP Credentials and RBAC Authentication**

* BIG-IP Credentials
```sh
kubectl create secret generic bigip-login -n kube-system --from-literal=username=admin --from-literal=password=dummy
```
* Create Service Account
```sh
kubectl create serviceaccount k8s-bigip-ctlr -n kube-system
```
* Create Cluster Role and Cluster Role Binding
```
# for reference only
# Should be improved as per your cluster requirements
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: bigip-ctlr-clusterrole
rules:
- apiGroups: ["", "extensions"]
  resources: ["nodes", "services", "endpoints", "namespaces", "ingresses", "pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["", "extensions"]
  resources: ["configmaps", "events", "ingresses/status"]
  verbs: ["get", "list", "watch", "update", "create", "patch"]
- apiGroups: ["cis.f5.com"]
  resources: ["virtualservers"]
  verbs: ["get", "list", "watch", "update"]
- apiGroups: ["", "extensions"]
  resources: ["secrets"]
  resourceNames: ["<secret-containing-bigip-login>"]
  verbs: ["get", "list", "watch"]
---

kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: bigip-ctlr-clusterrole-binding
  namespace: <controller_namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: bigip-ctlr-clusterrole
subjects:
- apiGroup: ""
  kind: ServiceAccount
  name: bigip-ctlr
  namespace: <controller_namespace>
```

**Supported Controller Modes: NodePort and Cluster**
* [CIS Architecture](https://clouddocs.f5.com/containers/v2/kubernetes/kctlr-modes.html)

**Add BIG-IP device to VXLAN**
* [Overview of CIS VXLAN](https://clouddocs.f5.com/containers/v2/kubernetes/flannel-bigip-info.html)
* [Configure VXLAN with CIS](https://clouddocs.f5.com/containers/v2/kubernetes/kctlr-use-bigip-k8s.html)

**Sample Configuration for reference**
* https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/config_examples/crd/basic

**Note**:: “--custom-resource-mode=true” deploys CIS in Custom Resource Mode.