# F5 CIS Service Type LoadBalancer deployed in EKS Anywhere

Amazon EKS Anywhere (EKS-A) is a Kubernetes installer based on and used by Amazon Elastic Kubernetes Service (EKS) to create reliable and secure Kubernetes clusters. This user-guide is created to document and validate F5 BIG-IP and F5 CIS integration with Amazon EKS Anywhere. More information on [EKS Anywhere](https://aws.amazon.com/eks/eks-anywhere/)

A service of type LoadBalancer is the simplest and the fastest way to expose a service inside a EKS Anywhere cluster to the external world. All you need to-do is specify the service type as type=LoadBalancer in the service definition.

Services of type LoadBalancer are natively supported in Kubernetes deployments. When you create a service of type LoadBalancer, Kubernetes spins up a service in integration with F5 IPAM Controller which allocates an IP address from the ip-range specified by the ipamlabel. Using CIS with services configured for type LoadBalancer, BIG-IP can load balance the incoming traffic to the Kubernetes cluster without having to create any ingress resource. CIS will manage the public IP addresses for the application using the F5 IPAM Controller. This cloud like simplification of load balancer resources could significantly reduce your operational expenses.

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/servicetypelb/diagrams/2021-08-17_16-44-33.png)

Demo on YouTube [video](https://youtu.be/eF_jxCuCS5Q)

Looking at the diagram, the following events occur:

1. CIS updates the service whenever the loadBalancer IP is empty.
2. F5 IPAM assigns an IP address for the loadBalancer: ingress: object from the ip-range ipamlabel specified by the annotation
3. Once the object is updated with the IP address, CIS configures BIG-IP with the External IP address as shown below

#### Example of deployed service using type LoadBalancer shown in the diagram

```
apiVersion: v1
kind: Service
metadata:
  annotations:
    cis.f5.com/ipamLabel: Test
  creationTimestamp: "2021-08-17T23:06:41Z"
  labels:
    app: f5-demo
  name: f5-demo
  namespace: default
  resourceVersion: "5035420"
  uid: ba6804e3-ef55-4487-a3ea-188aa4e0b106
spec:
  clusterIP: 10.107.224.128
  clusterIPs:
  - 10.107.224.128
  externalTrafficPolicy: Cluster
  ports:
  - name: f5-demo
    nodePort: 31913
    port: 80
    protocol: TCP
    targetPort: 80
  selector:
    app: f5-demo
  sessionAffinity: None
  type: LoadBalancer
status:
  loadBalancer:
    ingress:
    - ip: 192.168.15.45
```

## Configuring Service Type LoadBalancer

## Prerequisites

* Recommend AS3 version 3.30.0 [repo](https://github.com/F5Networks/f5-appsvcs-extension/releases/tag/v3.30.0)
* CIS 2.5.1 [repo](https://github.com/F5Networks/k8s-bigip-ctlr/releases/tag/v2.5.1)
* F5 IPAM Controller [repo](https://github.com/F5Networks/f5-ipam-controller/releases/tag/v0.1.4)

## Setup Options for the IPAM controller

CIS provides the following options for using the F5 IPAM controller with EKS Anywhere

* Defining the IPAM label in the service which maps to the IP-Range. In my example I am using the following 

  -  --ip-range='{"Test":"192.168.15.45-192.168.15.45"}'

The F5 IPAM Controller running inside EKS Anywhere can:

* Allocate IP address from static IP address pool based on the ipamlable defined in the service

**Note** The idea here is that you specify the ip-range label in the service and use service type load balancing. 

## Create the CIS Deployment Configuration

### Step 1

Add the parameter --ipam=true in the CIS deployment to provide the integration with CIS and IPAM

* --ipam=true

```
args: 
  - "--bigip-username=$(BIGIP_USERNAME)"
  - "--bigip-password=$(BIGIP_PASSWORD)"
  - "--bigip-url=192.168.14.45"
  - "--namespace=default"
  - "--bigip-partition=eks"
  - "--pool-member-type=nodeport"
  - "--log-level=DEBUG"
  - "--insecure=true"
  - "--custom-resource-mode=true"
  - "--as3-validation=true"
  - "--log-as3-response=true"
  - "--ipam=true"
```

Deploy CIS and CRD schema

```
kubectl create -f f5-cluster-deployment.yaml
kubectl create -f customresourcedefinitions.yaml
```

* cis-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/servicetypelb/cis-deployment/f5-cluster-deployment.yaml)
* crd-schema [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/servicetypelb/cis-deployment/customresourcedefinitions.yaml)

## F5 IPAM Deployment Configuration

### Step 2

* --orchestration=kubernetes

The orchestration parameter holds the orchestration environment i.e. Kubernetes

* --ip-range='{"Test":"192.168.15.45-192.168.15.45"}'

ip-range parameter holds the IP address ranges and from this range, it creates a pool of IP address range which gets allocated by the ipamlabel defined in the Service

* --log-level=debug

```
- args:
    - --orchestration=kubernetes
    - --ip-range='{"Test":"192.168.15.45-192.168.15.45"}'
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
$ kubectl logs -f deploy/f5-ipam-controller -n kube-system
2021/08/17 23:05:35 [DEBUG] Creating IPAM Kubernetes Client
2021/08/17 23:05:35 [INFO] [INIT] Starting: F5 IPAM Controller - Version: 0.1.4, BuildInfo: azure-453-9f505dd510b697a3b0058aefa7aace9ec4b519c3
2021/08/17 23:05:35 [DEBUG] [ipam] Creating Informers for Namespace kube-system
2021/08/17 23:05:35 [DEBUG] Created New IPAM Client
2021/08/17 23:05:35 [DEBUG] [MGR] Creating Manager with Provider: f5-ip-provider
2021/08/17 23:05:35 [DEBUG] [STORE] [id ipaddress status ipam_label]
2021/08/17 23:05:35 [DEBUG] [STORE]  1	 192.168.15.45 1 Test
2021/08/17 23:05:35 [INFO] [CORE] Controller started
2021/08/17 23:05:35 [INFO] Starting IPAMClient Informer
I0817 23:05:35.490602       1 shared_informer.go:240] Waiting for caches to sync for F5 IPAMClient Controller
2021/08/17 23:05:35 [DEBUG] Enqueueing on Create: kube-system/ipam.192.168.14.45.eks
I0817 23:05:35.593236       1 shared_informer.go:247] Caches are synced for F5 IPAMClient Controller 
2021/08/17 23:05:35 [DEBUG] K8S Orchestrator Started
2021/08/17 23:05:35 [DEBUG] Starting Custom Resource Worker
2021/08/17 23:05:35 [DEBUG] Processing Key: &{0xc000430580 <nil> Create}
2021/08/17 23:05:35 [DEBUG] Starting Response Worker
```

ipam-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/eks-anywhere/servicetypelb/ipam-deployment)


## Create the Service Type LoadBalancer Service

### Step 3

Create the pod deployments and services for the test application

```
kubectl create -f f5-demo-deployment.yaml
kubectl create -f f5-demo-service.yaml
```

pod-deployments [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/eks-anywhere/servicetypelb/pod-deployment)

## Logging output when the IPAM controller when the services are created

```
2021/08/17 23:06:43 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.14.45.eks
2021/08/17 23:06:43 [DEBUG] Processing Key: &{0xc000156420 0xc000430580 Update}
2021/08/17 23:06:43 [DEBUG] [CORE] Allocated IP: 192.168.15.45 for Request: 
Hostname: 	Key: default/f5-demo_svc	CIDR: 	IPAMLabel: Test	IPAddr: 	Operation: Create

2021/08/17 23:06:43 [DEBUG] [PROV] Created 'A' Record. Host:default/f5-demo_svc, IP:192.168.15.45
2021/08/17 23:06:43 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.14.45.eks
2021/08/17 23:06:43 [DEBUG] Updated: kube-system/ipam.192.168.14.45.eks with Status. With IP: 192.168.15.45 for Request: 
Hostname: 	Key: default/f5-demo_svc	CIDR: 	IPAMLabel: Test	IPAddr: 192.168.15.45	Operation: Create
```

## View the F5 IPAM Controller configuration

F5 IPAM Controller creates the following CRD to create the configuration between CIS and IPAM 

```
$ kubectl describe f5ipam -n kube-system
Name:         ipam.192.168.14.45.eks
Namespace:    kube-system
Labels:       <none>
Annotations:  <none>
API Version:  fic.f5.com/v1
Kind:         F5IPAM
Metadata:
  Creation Timestamp:  2021-08-17T23:05:27Z
  Generation:          2
  Managed Fields:
    API Version:  fic.f5.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:status:
        .:
        f:IPStatus:
    Manager:      f5-ipam-controller
    Operation:    Update
    Time:         2021-08-17T23:06:43Z
    API Version:  fic.f5.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:spec:
        .:
        f:hostSpecs:
    Manager:         k8s-bigip-ctlr.real
    Operation:       Update
    Time:            2021-08-17T23:06:43Z
  Resource Version:  5035419
  UID:               cd3ee048-6a8c-4e82-99d7-a06e5e442c57
Spec:
  Host Specs:
    Ipam Label:  Test
    Key:         default/f5-demo_svc
Status:
  IP Status:
    Ip:          192.168.15.45
    Ipam Label:  Test
    Key:         default/f5-demo_svc
Events:          <none>
```

## View the Service Type LoadBalancer status

Use the kubectl get service command to determine the EXTERNAL-IP that CIS will configure BIG-IP

```
$ kubectl get service
NAME         TYPE           CLUSTER-IP       EXTERNAL-IP     PORT(S)        AGE
f5-demo      LoadBalancer   10.107.224.128   192.168.15.45   80:31913/TCP   46m
```

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/servicetypelb/diagrams/2021-08-18_11-01-50.png)
