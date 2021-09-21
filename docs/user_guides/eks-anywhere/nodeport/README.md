# F5 CIS deployed in EKS Anywhere 

Amazon EKS Anywhere (EKS-A) is a Kubernetes installer based on and used by Amazon Elastic Kubernetes Service (EKS) to create reliable and secure Kubernetes clusters. This user-guide is created to document and validate F5 BIG-IP and F5 CIS integration with Amazon EKS Anywhere. More information on [EKS Anywhere](https://aws.amazon.com/eks/eks-anywhere/)

## The Easiest Way is Via a NodePort

NodePort is named quite literally like many other functional components within Kubernetes. It is an open port on every worker node in the cluster that has a pod for that service. When traffic is received on that open port, it directs it to a specific port on the ClusterIP for the service it is representing. In a single-node cluster this is very straight forward. In a multi-node cluster the internal routing can get more complicated. In that case its best using an F5 BIG-IP load balancer so you can spread traffic out across all the nodes and be able to handle failures a bit easier.

NodePort is great, but it has a few limitations. Ports available to NodePort are in the 30,000 to 32,767 range

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/nodeport/diagram/2021-08-18_16-06-49.png)

## Prerequisites

* Recommend AS3 version 3.30.0 [repo](https://github.com/F5Networks/f5-appsvcs-extension/releases/tag/v3.30.0)
* CIS 2.5.1 [repo](https://github.com/F5Networks/k8s-bigip-ctlr/releases/tag/v2.5.1)

### Step 1 Create the CIS Deployment Configuration

Change the logging level to INFO once deployed 

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
```

Deploy CIS

```
kubectl create secret generic bigip-login -n kube-system --from-literal=username=admin --from-literal=password=secret
kubectl create serviceaccount k8s-bigip-ctlr -n kube-system
kubectl create clusterrolebinding k8s-bigip-ctlr-clusteradmin --clusterrole=cluster-admin --serviceaccount=kube-system:k8s-bigip-ctlr
kubectl create -f f5-cluster-deployment.yaml
```

* cis-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/nodeport/cis-deployment/f5-cluster-deployment.yaml)

### Step 2 Create the APP Service and Deployment

Create the APP pod deployment and service

```
kubectl create -f f5-demo-test-service.yaml
kubectl create -f f5-demo-production-service.yaml
```

pod-deployments [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/eks-anywhere/nodeport/pod-deployment)

### Step 3 Create the CRD and Schema

Create the CRD to schema to configure BIG-IP with the public IP address to Ingress traffic into the EKS Anywhere cluster

```
kubectl create -f customresourcedefinitions.yaml
kubectl create -f vs-myapp.yaml
```

crd-example [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/eks-anywhere/nodeport/crd-example)

### Step 4 Validate virtual server connectivity 

Validate the virtual server configuration on the BIG-IP and connectivity to virtual server

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/nodeport/diagram/2021-08-18_16-11-08.png)

Connect to the external IP

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/nodeport/diagram/2021-08-18_16-36-04.png)

