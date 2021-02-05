# Integration with Nginx Ingress Controller

Using this integration CIS can be used to configure The F5 BIG-IP device as a load balancer for  [Nginx Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/) pods.

> **Feature Status**: The integration b/w CIS and Nginx Controller is available as a preview feature. It is suitable for experimenting and testing; however, it must be used with caution in production environments. Additionally, while the feature is in the preview, we might introduce some backward-incompatible changes in the next releases.

## Prerequisites 

1. These are the mandatory requirements for deploying CIS:

    * OpenShift/Kubernetes Cluster must be up and running
    * AS3: 3.18+
    * BIG-IP partition to create OpenShift/Kubernetes cluster objects which can be created on the BIG-IP using the following tmos command:
    
        create auth partition <cis_managed_partition>
    
    * You need a user with administrative access to this partition
    * If you need to pull the k8s-bigip-ctlr image from a private Doc.ker registry, store your Docker login credentials as a Secret.
    Additionally, if you are deploying the CIS in Cluster Mode you need to have following prerequisites. For more information, see [Deployment Options](https://clouddocs.f5.com/containers/latest/userguide/config-options.html#config-options).
    
        * You must have a fully active/licensed BIG-IP. SDN must be licensed. For more information, see [BIG-IP VE license support for SDN services](https://support.f5.com/csp/article/K26501111).
        * VXLAN tunnel should be configured from OpenShift/Kubernetes Cluster to BIG-IP. For more information see, [Creating VXLAN Tunnels](https://clouddocs.f5.com/containers/latest/userguide/cis-helm.html#creating-vxlan-tunnels).

2. Clone the CIS controller repo and change into the k8s-bigip-ctlr folder:
   
    ``git clone https://github.com/F5Networks/k8s-bigip-ctlr.git``

    ``cd k8s-bigip-ctlr/docs/_static/config_examples/crd/IngressLink/``

## Configuration 

### 1. Create the Proxy iRule on Bigip

* Login to BigIp GUI 
* On the Main tab, click Local Traffic > iRules.
* Click Create.
* In the Name field, type name as "Proxy_Protocol_iRule".
* In the Definition field, Copy the definition from "Proxy_Protocol_iRule" file.
Click Finished.

### 2. Install the CIS Controller 

Add BIG-IP credentials as Kubernetes Secrets.

    kubectl create secret generic bigip-login -n kube-system --from-literal=username=admin --from-literal=password=<password>

Create a service account for deploying CIS.

    kubectl create serviceaccount bigip-ctlr -n kube-system

Create a Cluster Role and Cluster Role Binding on the Kubernetes Cluster as follows:
    
    kubectl apply -f  cis-config/cis_rbac.yaml
    
Create IngressLink Custom Resource definition as follows:

    kubectl apply -f ingresslink-customresourcedefinition.yaml

Update the bigip address, partition and other details(image, imagePullSecrets, etc) in CIS deployment file and Install CIS Controller in nodeport mode as follows:

    kubectl apply -f  cis-config/cis_deploy.yaml
    
Note: To deploy the CIS controller in cluster mode update CIS deploymemt arguments as follows for kubernetes.

    args:
    - --pool-member-type=cluster
    - --flannel-name=/test/vxlan-tunnel-mp 
    . . .
 

### 3. Nginx-Controller Installation

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

### 4. Create an IngressLink Resource
    
Update the ip-address in IngressLink resource and iRule which is created in Step-1. This ip-address will be used to configure the BIG-IP device to load balance among the Ingress Controller pods.

    kubectl apply -f ingresslink.yaml

Note: The name of the app label selector in IngressLink resource should match the labels of the nginx-ingress service created in step-3.

### 5. Test the Integration

Now to test the integration let's deploy a sample ingress.

    kubectl apply -f ingress-example

The Ingress Controller pods are behind the IP configured in Step 4.

Let's test the traffic:

    $ curl --resolve cafe.example.com:443:192.168.10.5 https://cafe.example.com:443/coffee --insecure
    Server address: 10.12.0.18:80
    Server name: coffee-7586895968-r26zn
    ...
    