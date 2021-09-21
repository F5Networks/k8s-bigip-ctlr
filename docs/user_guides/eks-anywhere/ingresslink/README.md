# F5 IngressLink Deployed in EKS Anywhere

Amazon EKS Anywhere (EKS-A) is a Kubernetes installer based on and used by Amazon Elastic Kubernetes Service (EKS) to create reliable and secure Kubernetes clusters. This user-guide is created to document and validate F5 BIG-IP and F5 CIS + NGINX integration with Amazon EKS Anywhere. More information on [EKS Anywhere](https://aws.amazon.com/eks/eks-anywhere/)

The F5 IngressLink is addressing modern app delivery at scale/large. IngressLink is a resource definition defined between BIG-IP and Nginx using F5 Container Ingress Service and Nginx Ingress Service. The purpose of this user guide is to documented and simply the configuration and steps required to configure Ingresslink deployed in EKS Anywhere. This user-guide wont cover deploying of EKS Anywhere

F5 IngressLink was the first true integration between BIG-IP and NGINX technologies. F5 IngressLink was built to support customers with modern, container application workloads that use both BIG-IP Container Ingress Services and NGINX Ingress Controller for Kubernetes. It’s an elegant control plane solution that offers a unified method of working with both technologies from a single interface—offering the best of BIG-IP and NGINX and fostering better collaboration across NetOps and DevOps teams. The diagram below demonstrates this use-case.

![architecture](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/diagram/2021-08-17_12-08-07.png)

Demo on YouTube [video](https://youtu.be/3BlOCWRSWbU)

On this page you’ll find:

* Links to the GitHub repositories for all the requisite software
* Documentation for the solution(s)
* A step by step configuration and deployment guide for F5 IngressLink

## EKS Anywhere + F5 IngressLink Compatibility Matrix

Validated versions to use IngressLink:

* Recommend AS3 version 3.30.0 [repo](https://github.com/F5Networks/f5-appsvcs-extension/releases/tag/v3.30.0)
* CIS 2.5.1 [repo](https://github.com/F5Networks/k8s-bigip-ctlr/releases/tag/v2.5.1)
* NGINX+ IC [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/eks-anywhere/ingresslink/nginx-config)
* Product Documentation [documentation](https://clouddocs.f5.com/containers/latest/userguide/ingresslink/)

## Configure F5 IngressLink with Kubernetes

**Step 1:**

### Create the  Proxy Protocol iRule on Bigip

Proxy Protocol is required by NGINX to provide the applications PODs with the original client IPs. Use the following steps to configure the Proxy_Protocol_iRule

* Login to BigIp GUI 
* On the Main tab, click Local Traffic > iRules.
* Click Create.
* In the Name field, type name as "Proxy_Protocol_iRule".
* In the Definition field, Copy the definition from "Proxy_Protocol_iRule" file. Click Finished.

proxy_protocol_iRule [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/big-ip/proxy-protocal/irule)

**Step 2**

### Install the CIS Controller 

Add BIG-IP credentials as Kubernetes Secrets

    kubectl create secret generic bigip-login -n kube-system --from-literal=username=admin --from-literal=password=<password>

Create a service account for deploying CIS.

    kubectl create serviceaccount bigip-ctlr -n kube-system

Create a Cluster Role and Cluster Role Binding on the Kubernetes Cluster as follows:
    
    kubectl create clusterrolebinding k8s-bigip-ctlr-clusteradmin --clusterrole=cluster-admin --serviceaccount=kube-system:k8s-bigip-ctlr
    
Create CIS IngressLink Custom Resource definition schema as follows:

    kubectl create -f customresourcedefinition.yaml

cis-crd-schema [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/cis/cis-crd-schema/customresourcedefinition.yaml)

Update the bigip address, partition and other details(image, imagePullSecrets, etc) in CIS deployment file and Install CIS Controller in ClusterIP mode as follows:

* Add the following statements to the CIS deployment arguments for Ingresslink

    - "--custom-resource-mode=true"

* To deploy the CIS controller in nodeport mode update CIS deployment arguments as follows for kubernetes.

    - "--pool-member-type=nodeport"

```
kubectl create -f f5-cis-deployment.yaml
```

cis-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/cis/cis-deployment/f5-cis-deployment.yaml)

Use the commands below to validate that CIS is running

    $ kubectl get pods -n kube-system
    k8s-bigip-ctlr-deployment-7b5d7cd685-wz5cg   1/1     Running   0          6d22h

You can view the CIS logs using the following

**Note** CIS log level is currently set to DEBUG. Recommend using logging INFO. This can be changed in the CIS controller arguments 

    kubectl logs -f deploy/k8s-bigip-ctlr-deployment -n kube-system | grep --color=auto -i '\[debug'

**Step 3**

### Nginx-Controller Installation

Create NGINX IC custom resource definitions for VirtualServer and VirtualServerRoute, TransportServer and Policy resources:

    kubectl apply -f k8s.nginx.org_virtualservers.yaml
    kubectl apply -f k8s.nginx.org_virtualserverroutes.yaml
    kubectl apply -f k8s.nginx.org_transportservers.yaml
    kubectl apply -f k8s.nginx.org_policies.yaml

crd-schema [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/eks-anywhere/ingresslink/nginx-config/crd-schema)

Create a namespace and a service account for the Ingress controller:
   
    kubectl apply -f nginx-config/ns-and-sa.yaml
   
Create a cluster role and cluster role binding for the service account:
   
    kubectl apply -f nginx-config/rbac.yaml
   
Create a secret with a TLS certificate and a key for the default server in NGINX:

    kubectl apply -f nginx-config/default-server-secret.yaml
    
Create a config map for customizing NGINX configuration:

    kubectl apply -f nginx-config/nginx-config.yaml
    
Create an IngressClass resource (for Kubernetes >= 1.18):  
    
    kubectl apply -f nginx-config/ingress-class.yaml

Use a Deployment. When you run the Ingress Controller by using a Deployment, by default, Kubernetes will create one Ingress controller pod.
    
    kubectl apply -f nginx-config/nginx-ingress.yaml
  
Create a service for the Ingress Controller pods for ports 80 and 443 as follows:

    kubectl apply -f nginx-config/nginx-service.yaml

**Note** CIS monitors the NGINX IC readiness-port. When using nodeport mode you need to expose the ports in the service as shown below 

```
port: 8081
targetPort: 8081
protocol: TCP
name: readiness-port
```

Verify NGINX-Ingress deployment

```
$ kubectl get pods -n nginx-ingress
NAME                           READY   STATUS    RESTARTS   AGE
nginx-ingress-7fc84bb9-4rjwr   1/1     Running   0          6d22h
nginx-ingress-7fc84bb9-fhbdw   1/1     Running   0          6d22h
nginx-ingress-7fc84bb9-fp49c   1/1     Running   0          6d22h
nginx-ingress-7fc84bb9-gc4lj   1/1     Running   0          6d22h
```

nginx-config [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/eks-anywhere/ingresslink/nginx-config)

**Step 4**

### Create an IngressLink Resource

Update the ip-address in IngressLink resource and iRule which is created in Step-1. This ip-address will be used to configure the BIG-IP device to load balance among the Ingress Controller pods.

    kubectl apply -f vs-ingresslink.yaml

Note: The name of the app label selector in IngressLink resource should match the labels of the nginx-ingress service created in step-3.

crd-resource [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/cis/crd-resource/vs-ingresslink.yaml)

**Step 5**

### Deploy the Cafe Application

Create the coffee and the tea deployments and services:

    kubectl create -f cafe.yaml

### Configure Load Balancing for the Cafe Application

Create a secret with an SSL certificate and a key:

    kubectl create -f cafe-secret.yaml

Create an Ingress resource:
```
kubectl create -f cafe-ingress.yaml
```
cafe application [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/eks-anywhere/ingresslink/ingress-example)

**Step 6**

### Test the Application

1. To access the application, curl the coffee and the tea services. We'll use ```curl```'s --insecure option to turn off certificate verification of our self-signed
certificate and the --resolve option to set the Host header of a request with ```cafe.example.com```
    
To get coffee:

![coffee](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/diagram/2021-08-17_12-39-25.png)

If your prefer tea:

![tea](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/diagram/2021-08-17_12-39-01.png)

As you can see, the Ingress Controller reported the BIG-IP IP address (configured in IngressLink resource) in the ADDRESS field of the Ingress status.

### BIG-IP Pool Members

CIS is configured to use NodePort. BIG-IP pool-members will be the EKS Anywhere nodes. As this cluster has two nodes the BIG-IP pool members will be 192.168.200.26 and 192.168.200.26. **Note:** When using NodePort its recommend to use node label. Node labels will only add nodes to the BIG-IP with the associated node label.
```
$ kubectl get nodes -o wide
NAME                                STATUS   ROLES                  AGE     VERSION              INTERNAL-IP      EXTERNAL-IP      OS-IMAGE             KERNEL-VERSION     CONTAINER-RUNTIME
eks-cluster-85cdm                   Ready    control-plane,master   7d14h   v1.20.7-eks-1-20-2   192.168.200.26   192.168.200.26   Ubuntu 20.04.2 LTS   5.4.0-77-generic   containerd://1.4.4
eks-cluster-md-0-6cd695b8f4-7jj5q   Ready    <none>                 7d14h   v1.20.7-eks-1-20-2   192.168.200.27   192.168.200.27   Ubuntu 20.04.2 LTS   5.4.0-77-generic   containerd://1.4.4
```
To view the IngressLink virtual server:

![virtual server list](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/diagram/2021-08-17_12-53-53.png)

To view the IngressLink pool members:

![pool members](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/diagram/2021-08-17_12-54-23.png)

To view the IngressLink pool:

![pool list](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/diagram/2021-08-17_12-54-47.png)

To view the IngressLink pool members for port 443:

![pool members 443](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/diagram/2021-08-17_12-55-08.png)

To view the IngressLink pool members for 192.168.200.26:

![pool members 192.168.200.26](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/eks-anywhere/ingresslink/diagram/2021-08-17_13-27-07.png)

**Step 8**

### Troubleshooting IngressLink

Check the CIS API communication with BIG-IP using DEBUG logging. Below is a successful deployment of the ingresslink resource

```
$ kubectl logs -f deploy/k8s-bigip-ctlr-deployment -n kube-system | grep --color=auto -i '\[as3'
2021/08/17 19:43:32 [DEBUG] [AS3] PostManager Accepted the configuration
2021/08/17 19:43:32 [DEBUG] [AS3] posting request to https://192.168.14.45/mgmt/shared/appsvcs/declare/
2021/08/17 19:43:36 [DEBUG] [AS3] Response from BIG-IP: code: 200 --- tenant:ingresslink --- message: success
```

Check the ingresslink resource 

    $ kubectl get ingresslink -n nginx-ingress
    NAME             AGE
    vs-ingresslink   13m

Check the ingresslink resource configuration

```
$ kubectl get ingresslink -n nginx-ingress -o yaml
apiVersion: v1
items:
- apiVersion: cis.f5.com/v1
  kind: IngressLink
  metadata:
    creationTimestamp: "2021-08-17T19:43:54Z"
    generation: 1
    managedFields:
    - apiVersion: cis.f5.com/v1
      fieldsType: FieldsV1
      fieldsV1:
        f:spec:
          .: {}
          f:iRules: {}
          f:selector:
            .: {}
            f:matchLabels:
              .: {}
              f:app: {}
          f:virtualServerAddress: {}
      manager: kubectl-create
      operation: Update
      time: "2021-08-17T19:43:54Z"
    name: vs-ingresslink
    namespace: nginx-ingress
    resourceVersion: "4943181"
    uid: d814a91e-a46c-4f14-983e-c28c8a2409ee
  spec:
    iRules:
    - /Common/Proxy_Protocol_iRule
    selector:
      matchLabels:
        app: nginx-ingress
    virtualServerAddress: 192.168.15.46
kind: List
metadata:
  resourceVersion: ""
  selfLink: ""
```

For Nginx Ingress troubleshooting please use the following link https://kubernetes.github.io/ingress-nginx/troubleshooting/
