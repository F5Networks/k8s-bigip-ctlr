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
### 3. Install the CIS Controller.

* Refer to [CIS MultiCluster Default Mode](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/2.x-master/docs/config_examples/multicluster/default-mode/README.md) to install Container Ingress Services in default mode.

### 4. Install the Nginx Ingress Controller.

* Refer to [Integration with F5 Container Ingress Services](https://docs.nginx.com/nginx-ingress-controller/installation/integrations/f5-ingresslink/) to deploy NGINX Ingress Controller.

* You can configure the NGINX Ingress Controller Readiness in the nginx-ingress-ingresslink service by exposing port 8081, which is used by BIGIP to monitor NGINX Ingress Controller’s readiness.

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
      nodePort: 32418
  selector:
    app: nginx-ingress
  type: NodePort
```
**Note**:
Use fixed nodePort in nginx-ingress service for monitor port 8081 in all the clusters. This is required to use same monitor across multiple cluster pools per ingresslink resource.

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
      selector:
        matchLabels:
          app: ingresslink
    - clusterName: cluster2
      namespace: nginx-ingress
      selector:
        matchLabels:
          app: ingresslink
  tls:
    clientSSLs:
      - wc-example-secret
    reference: secret
    serverSSLs:
      - wc-example-secret
  virtualServerAddress: 10.8.3.11
```
##### Note:
1. The name of the app label selector in IngressLink resource should match the labels of the service which exposes the NGINX Ingress Controller.
2. The service which exposes the NGINX Ingress Controller should be of type ``nodeport``.

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
