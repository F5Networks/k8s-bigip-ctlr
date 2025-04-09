# MultiCluster IngressLink Configuration for Default Mode

## Overview
F5 IngressLink Multi-Cluster is an integrated solution that enables seamless traffic management across multiple Kubernetes clusters using F5's BIG-IP and NGINX.

## Configuration

### 1.  Create IngressLink Custom Resource Definition

Create IngressLink Custom Resource definition as follows:

    ```sh
    export CIS_VERSION=<cis-version>
    # For example
    # export CIS_VERSION=v2.12.0
    # or
    # export CIS_VERSION=2.x-master
    #
    # the latter if using a CIS image with :latest label
    #

    kubectl create -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/${CIS_VERSION}/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml
    ```
### 2. Install the CIS Controller.

* Refer to [CIS MultiCluster Default Mode](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/multicluster/default-mode/README.md) to install Container Ingress Services in default mode.

### 3. Create the Proxy Protocol iRule on BIG-IP (Optional).

* Login to the BIG-IP GUI.
* On the Main tab, click **Local Traffic > iRules**.
* Click **Create**.
* In the Name field, type name as "Proxy_Protocol_iRule".
* In the Definition field, Copy the definition from [Proxy_Protocol_iRule](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResource/IngressLink/Proxy_Protocol_iRule) file.
* Click **Finished**.

For accepting the PROXY Protocol nginx-ingress needs below configuration in nginx configmap resource.This is documented in step5
```
proxy-protocol: "True"
real-ip-header: "proxy_protocol"
set-real-ip-from: "0.0.0.0/0"

```
In the ConfigMap resource enable the proxy protocol, which the BIG-IP system will use to pass the client IP and port information to NGINX. For the set-real-ip-from key, use the subnet of the IP which the BIG-IP system uses to send traffic to NGINX

**Note**: 
* Proxy Protocol iRule is used to send client ip, loadbalancer ip and port information to nginx-ingress-controller. This information can be used by nginx-ingress for specific usecases like keeping a denylist of IP addresses, or simply for logging and statistics purposes.

### 4. Install the Nginx Ingress Controller.

#### Installation with helm

1. Install the crds
    ```
   kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v4.0.1/deploy/crds.yaml
   
   ```
2. Get the helm chart and update values.yaml with changes required
   ```
   helm pull oci://ghcr.io/nginx/charts/nginx-ingress --untar --version 2.0.1
   
    ```
3. Configuration required for CIS integration
    ```
    controller:
      config:
        entries:
          proxy-protocol: "True"
          real-ip-header: "proxy_protocol"
          set-real-ip-from: "0.0.0.0/0"
      reportIngressStatus:
        ingressLink: nginx-ingress
      service:
        type: ClusterIP
        externalTrafficPolicy: Cluster
        extraLabels:
          app: ingresslink
    ```
   **Note**: 
   * **ingressLink** in **reportIngressStatus** config refers to the name of the ingresslink resource created.report-ingress-status enables reporting ingress statuses which updates ingress address field from virtualaddress assigned to ingresslink resource. 
   
4. configure the NGINX Ingress Controller Readiness in the nginx-ingress-ingresslink service by exposing port 8081, which is used by BIGIP to monitor NGINX Ingress Controller’s readiness if no monitor provided in ingresslink resource.
    
    ```
    apiVersion: v1
    kind: Service
    metadata:
      annotations:
      name: nginx-ingress
      namespace: nginx-ingress
      labels:
        app: ingresslink
    spec:
      ports:
        - name: nginx-80
          port: 80
          protocol: TCP
          targetPort: 80
        - name: nginx-443
          port: 443
          protocol: TCP
          targetPort: 443
        - port: 8081
          targetPort: 8081
          protocol: TCP
          name: readiness-port
      selector:
        app: nginx-ingress
      type: NodePort
    ```

5. Install the helm chart
   ```
   helm install <release_name> <chart> --namespace nginx-ingress --create-namespace
    ```
   Refer[values.yaml](values.yaml)for sample config required for CIS integration
   Refer to [Integration with F5 Container Ingress Services](https://docs.nginx.com/nginx-ingress-controller/installation/integrations/f5-ingresslink/) for nginx f5ingresslink integration

### 5. Create an IngressLink Resource.

```
apiVersion: cis.f5.com/v1
kind: IngressLink
metadata:
  name: nginx-ingress
  namespace: nginx-ingress
spec:
  host: '*.example.com'
  multiClusterServices:
  - clusterName: cluster1
    namespace: nginx-ingress
    service: nginx-ingress
  - clusterName: cluster2
    namespace: nginx-ingress
    service: nginx-ingress
  monitors:
  - name: /Common/nginx-ingresslink-monitor
    reference: bigip 
  tls:
    clientSSLs:
    - wc-example-secret
    reference: secret
    serverSSLs:
    - wc-example-secret
  virtualServerAddress: 10.8.3.11
```
##### Note:

The service which exposes the NGINX Ingress Controller should be of type ``nodeport``.

### 6. Test the Integration.

To test the integration, deploy a sample application:

    kubectl apply -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResource/IngressLink/ingress-example/cafe.yaml
    kubectl apply -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResource/IngressLink/ingress-example/cafe-secret.yaml
    kubectl apply -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/customResource/IngressLink/ingress-example/cafe-ingress.yaml

The Ingress Controller pods are behind the IP configured in Step 5 (virtualServerAddress parameter).

To test the traffic (in this example we used 10.8.3.11 as our VirtualServerAddress):

    $ curl --resolve cafe.example.com:443:10.8.3.11 https://cafe.example.com:443/coffee --insecure
    Server address: 10.12.0.18:80
    Server name: coffee-7586895968-r26zn
    ...

Verify the ip address status on ingress resource
    
    kubectl get ingress
    NAME           CLASS   HOSTS              ADDRESS     PORTS     AGE
    cafe-ingress   nginx   cafe.example.com   10.8.3.11   80, 443   29d

**Known Issues**:
* In multicluster mode, ingress ip address is updated only on cluster where ingresslink resource resides.