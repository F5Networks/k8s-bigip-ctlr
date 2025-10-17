CIS Installation with Health Server

## Overview
CIS can be configured for Kubernetes and OpenShift, varying by resources (ConfigMap, Ingress, Routes, CRD, serviceTypeLB), BIG-IP deployment (stand alone, HA), and cluster networking (Flannel/Calico/Cilium/Antrea/OVNKuberentes).
In this document we will see how CIS is installed with Webhooks for validating and defaulting the custom resources.

## Prerequisites

These are the mandatory requirements for deploying CIS:

* OpenShift/Kubernetes Cluster must be up and running.

* AS3: 3.18+ must be installed on your BIG-IP system.

* Use the latest TLS version and cipher suites in Kubernetes for kube-api.

* Create a BIG-IP partition to manage Kubernetes objects. This partition can be created either via the GUI (System > Users > Partition List) or via our TMOS CLI:
  ```shell
  create auth partition <cis_managed_partition>
  ```

* You need a user with administrative access to this partition.

* If you need to pull the k8s-bigip-ctlr image from a private Docker registry, store your Docker login credentials as a Secret.

Additionally, if you are using VXLan in Cluster Mode you need to have the following prerequisites. For more information, see [BIG IP Networking with CIS](https://clouddocs.f5.com/containers/latest/userguide/config-options.html#config-options).

* You must have a fully active/licensed BIG-IP. SDN must be licensed. For more information, see BIG-IP VE license support for SDN services.
* VXLan tunnel should be configured from OpenShift/Kubernetes Cluster to BIG-IP. For more information, see [Creating VXLAN Tunnels](#Creating-VXLAN-Tunnels).

Also consider  [BIG IP Networking with CIS](https://clouddocs.f5.com/containers/latest/userguide/config-options.html#config-options).

For BIG-IP HA, see [Deploying CIS with BIG-IP HA](https://clouddocs.f5.com/containers/latest/userguide/cis-deployment-options.html)

## Installing CIS Manually

* Clone the GitHub repository
  ```shell
  git clone https://github.com/F5Networks/k8s-bigip-ctlr.git
  ```
* Download the CA/BIG IP certificate and use it with CIS controller.
  * For Kubernetes, use the following command:
    ```shell
    echo | openssl s_client -showcerts -servername <server-hostname>  -connect <server-ip-address>:<server-port> 2>/dev/null | openssl x509 -outform PEM > server_cert.pem
    kubectl create configmap trusted-certs --from-file=./server_cert.pem -n kube-system
    ```
  * For Openshift, use the following command:
    ```shell
    echo | openssl s_client -showcerts -servername <server-hostname>  -connect <server-ip-address>:<server-port> 2>/dev/null | openssl x509 -outform PEM > server_cert.pem
    oc create configmap trusted-certs --from-file=./server_cert.pem -n kube-system
    ```

Alternatively, for non-prod environment you can use ```--insecure=true``` parameter.

**Note:-** If you are updating the BIGIP/CA Certificates, don't miss to rotate them on k8s cluster and restart the CIS.
* * Create a Cluster Role, Cluster Role Binding and Service account for CIS Controller
* For Kubernetes, use the following command:
  ```shell
  kubectl create -f ./docs/config_examples/rbac/k8s_rbac.yml
  ```
* For Openshift, use the following command:
  ```shell
  oc create -f ./docs/config_examples/rbac/openshift_rbac.yaml
  ```
**Note:-** The command has the broadest supported permission set. You can narrow the permissions down to specific resources, namespaces, etc. to suit your needs. See the [Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) for more information.
**Important:** You can substitute a Role and RoleBinding if your Controller does not need access to the entire Cluster.
* Install Custom Resource Definitions for CIS Controller if you are using [custom resources](https://clouddocs.f5.com/containers/latest/userguide/crd/) or [nextGen Routes](https://clouddocs.f5.com/containers/latest/userguide/next-gen-routes/) or [multi-cluster](https://clouddocs.f5.com/containers/latest/userguide/multicluster/)
  * For Kubernetes, use the following command:
    ```shell
      export CIS_VERSION=<cis-version>
      # For example
      # export CIS_VERSION=v2.20.0
      # or
      # export CIS_VERSION=2.x-master
      # the latter if using a CIS image with :latest label
      kubectl create -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/${CIS_VERSION}/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml
    ```
  * For Openshift, use the following command:
    ```shell
    export CIS_VERSION=<cis-version>
    # For example
    # export CIS_VERSION=v2.20.0
    # or
    # export CIS_VERSION=2.x-master
    # the latter if using a CIS image with :latest label
    oc create -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/${CIS_VERSION}/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml
    ```
* Mandatory with [nextGen Routes](https://clouddocs.f5.com/containers/latest/userguide/next-gen-routes/), Modify the extended ConfigMap file as required and deploy it
  ```shell
  oc create -f ./docs/config_examples/next-gen-routes/configmap/extendedRouteConfigwithBaseConfig.yaml
  ```
* Create the kubernetes secret with BIG IP credentials
  * For Kubernetes, use the following command:
      ```shell
      kubectl create secret generic f5-bigip-ctlr-login -n kube-system --from-literal=username=admin --from-literal=password=<password> --from-literal=url=<bigip-uri>
      ```
  * For Openshift, use the following command:
    ```shell
    oc create secret generic f5-bigip-ctlr-login -n kube-system --from-literal=username=admin --from-literal=password=<password> --from-literal=url=<bigip-uri>
    ```
* Optionally Install cert-manager, If it's not already installed in your cluster. This is required for CIS Webhook server to issue TLS certificates.
  * Create Namespace
    * For Kubernetes, use the following command:
      ```shell
      kubectl create namespace cert-manager
      ```
    * For OpenShift, use the following command:
      ```shell
      oc create namespace cert-manager
      ```
  * Add Helm Repo and Install
     ```shell
     helm repo add jetstack https://charts.jetstack.io
     helm repo update
     helm install cert-manager jetstack/cert-manager --namespace cert-manager 
     ``` 
    Note:- Helm should be installed on your jumpbox. For more information, see [Installing Helm](https://helm.sh/docs/intro/install/).
  * Ensure cert-manager pods are running:
    * For Kubernetes, use the following command:
      ```shell
      kubectl get pods -n cert-manager
      ```
    * For OpenShift, use the following command:
      ```shell
      oc get pods -n cert-manager
      ```

  Note:- Also follow the best practices for cert-manager installation as mentioned in the [cert-manager best practices](https://cert-manager.io/docs/installation/best-practice/).

* Create a Secure Issuer
  * For Kubernetes, use the following command:
    ```shell
    kubectl apply -f ./docs/config_examples/Install/health-server/issuer.yaml
    ```
  * For OpenShift, use the following command:
    ```shell
    oc apply -f ./docs/config_examples/Install/health-server/issuer.yaml
    ```

* Issue TLS Certificate for Webhook Server
  * For Kubernetes, use the following command:
    ```shell
    kubectl apply -f ./docs/config_examples/Install/health-server/certificate.yaml
    ```
  * For OpenShift, use the following command:
    ```shell
    oc apply -f ./docs/config_examples/Install/health-server/certificate.yaml
    ```
* Verify status for the certificate
  * For Kubernetes, use the following command:
    ```shell
    kubectl describe certificate cis-health-server-cert -n kube-system
    ```
  * For OpenShift, use the following command:
    ```shell
    oc describe certificate cis-health-server-cert -n kube-system
    ```

* Update the CIS deployment file with required image and [config parameters](https://clouddocs.f5.com/containers/latest/userguide/config-parameters.html) and install the CIS Controller.

  * For Kubernetes, use following cmd:
    ```shell
    kubectl create -f ./docs/config_examples/Install/health-server/sample-k8s-bigip-ctlr.yaml
    ```
  * For Openshift, use following cmd:
    ```shell
    oc create -f ./docs/config_examples/Install/health-server/sample-k8s-bigip-ctlr.yaml
    ```
* Create a Kubernetes Service for CIS

  * For Kubernetes, use following cmd:
    ```shell
    kubectl create -f ./docs/config_examples/Install/health-server/cis-service.yaml
    ```
  * For Openshift, use following cmd:
    ```shell
    oc create -f ./docs/config_examples/Install/health-server/cis-service.yaml
    ```

### Uninstalling CIS

* To uninstall CIS, run the following commands:

  * For Kubernetes, use following cmd:
    ```shell
    kubectl delete -f ./docs/config_examples/Install/health-server/cis-service.yaml
    kubectl delete -f ./docs/config_examples/Install/k8s/sample-k8s-bigip-ctlr.yaml
    kubectl delete -f ./docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml
    kubectl delete -f ./docs/config_examples/rbac/k8s_rbac.yml
    kubectl delete -f ./docs/config_examples/Install/health-server/certificate.yaml
    kubectl delete -f ./docs/config_examples/Install/health-server/issuer.yaml
    ```
  * For Openshift, use following cmd:
    ```shell
    oc delete -f ./docs/config_examples/Install/health-server/cis-service.yaml
    oc delete -f ./docs/config_examples/Install/openshift/f5-k8s-bigip-ctlr-openshift.yaml
    oc delete -f ./docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml
    oc delete -f ./docs/config_examples/Install/health-server/certificate.yaml
    kubectl delete -f ./docs/config_examples/Install/health-server/issuer.yaml
    ```
* Optionally, Uninstall cert-manager
  ```shell
  helm delete cert-manager --namespace cert-manager
  helm repo remove jetstack
  ```

* Optionally, Run the command to delete the secrets and namespace created.
  * For Kubernetes, use the following command:
    ```shell
    kubectl delete namespace cert-manager
    kubectl delete secret f5-bigip-ctlr-login -n kube-system
    kubectl delete secret cis-health-server-tls -n kube-system
    ```
  * For Openshift, use the following command:
    ```shell
    oc delete namespace cert-manager
    oc delete secret f5-bigip-ctlr-login -n kube-system
    oc delete secret cis-health-server-tls -n kube-system
    ```
* Mandatory with [nextGen Routes](https://clouddocs.f5.com/containers/latest/userguide/next-gen-routes/), Run the command to delete the extended cm.
  ```shell
    oc delete -f ./docs/config_examples/next-gen-routes/configmap/extendedRouteConfigwithBaseConfig.yaml
    ```
* Delete the trusted certs configMap
  * For Kubernetes, use the following command:
    ```shell
    kubectl delete configmap trusted-certs -n kube-system
    rm -rf server_cert.pem ca.crt
    ```
  * For OpenShift, use the following command:
    ```shell
    oc delete configmap trusted-certs -n kube-system
    rm -rf server_cert.pem ca.crt
    ```

## Creating VXLAN Tunnels

This section is required only if you plan to use CIS in a ClusterIP Deployment. See [BIG IP Networking with CIS](https://clouddocs.f5.com/containers/latest/userguide/config-options.html#config-options) for more information.

### Creating VXLAN Tunnels on Kubernetes Cluster

This configuration is for Standalone BIG-IP.
* Log in to BIG-IP and create a partition called kubernetes for CIS.
  ```shell
  tmsh create auth partition kubernetes
  ```
* Create a VXLAN profile.
  ```shell
  tmsh create net tunnels vxlan fl-vxlan port 8472 flooding-type none
  ```
* Create a VXLAN tunnel.
  ```shell
  tmsh create net tunnels tunnel fl-vxlan key 1 profile fl-vxlan local-address 10.1.1.4
  ```
* Create the VXLAN tunnel self IP.
  ```shell
  tmsh create net self 10.1.1.4 address 10.244.20.4/255.255.0.0 allow-service none vlan fl-vxlan
  ```
* Save the configuration.
  ```shell
  tmsh save sys config
  ```
* Before deploying CIS in ClusterIP mode, you need to configure BIG-IP as a node in the Kubernetes cluster. To do so you will need to modify ```./docs/config_examples/Install/k8s/bigip-node.yaml``` with the MAC address auto-created from the previous steps. From the jumpbox terminal, run the following command at bigip1. Copy the displayed MAC Address.
  ```shell
  tmsh show net tunnels tunnel k8s-tunnel all-properties
  ```
* Update the MAC address obtained in ```./docs/config_examples/Install/k8s/bigip-node.yaml```
* Create the BIG-IP node:
  ```shell
  kubectl create -f ./docs/config_examples/Install/k8s/bigip-node.yaml
  ```
* Verify “bigip1” node is created:
  ```shell
  kubectl get nodes
  ```

### Creating VXLAN Tunnels on Openshift Cluster for OpenshiftSDN CNI
This configuration is for Standalone BIG-IP.

* Log in to the BIG-IP and create net tunnels vxlan vxlan-mp flooding-type multipoint on BIG-IP.
  ```shell
  create net tunnels vxlan vxlan-mp flooding-type multipoint
  create net tunnels tunnel openshift_vxlan key 0 profile vxlan-mp local-address 10.1.1.4
  ```
* Add the BIG-IP device to the OpenShift overlay network.
  ```shell
  create net self 10.131.0.83/14 allow-service all vlan openshift_vxlan
  ```
* Create a new HostSubnet for BIG-IP on the OpenShift/Kubernetes cluster. This will provide the subnet for creating the tunnel self IP.
  ```shell
  oc create -f .docs/config_examples/Install/openshift/StandAlone/f5-kctlr-openshift-hostsubnet.yaml
  ```

* Verify “bigip1” node is created:
  ```shell
  oc get nodes
  ```