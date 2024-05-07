# Integration with Nginx Ingress Controller

Using this integration, CIS can be used to configure the F5 BIG-IP device as a load balancer for  [Nginx Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/) pods.

> **Feature Status**: The integration between CIS and Nginx Controller is available as a preview feature. It is suitable for experimenting and testing; however, it must be used with caution in production environments. Additionally, while the feature is in preview, we might introduce some backward-incompatible changes in the next releases. *The preview of the IngressLink solution requires a dedicated Container Ingress Services instance.*

## IngressLink Compatibility Matrix
Minimum version to use IngressLink:

| CIS | BIGIP | NGINX+ IC | AS3 |
| ------ | ------ | ------ | ------ |
| 2.3+ | v13.1+ | 1.10+ | 3.18+ | 

With CIS 3.x:

| CIS 3.x | BIGIP-Next       | CM             | NGINX+ IC |
| ------ |------------------|----------------|-----------|
| 3.0.0-beta | v20.2.0-2.375.1+ | 20.2.0-0.5.41+ |  1.10+    |


## Configuration

### 1.  Create IngressLink Custom Resource Definition

Create IngressLink Custom Resource definition as follows:

    ```
    kubectl create -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/cis-3.x/config_examples/customResourceDefinitions/customresourcedefinitions.yml
    ```


### 2. Create the Proxy iRule on BIG-IP.

* Login to the BIG-IP GUI.
* On the Main tab, click **Local Traffic > iRules**.
* Click **Create**.
* In the Name field, type name as "Proxy_Protocol_iRule".
* In the Definition field, Copy the definition from [Proxy_Protocol_iRule](https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResource/IngressLink/Proxy_Protocol_iRule) file.
* Click **Finished**.

### 3. Install the CIS Controller.

* Refer to [CIS Installation guide](https://clouddocs.f5.com/containers/latest/userguide/cis-helm.html) to install Container Ingress Services on Kubernetes or Openshift.
* Make sure that you deploy CIS in CRD mode (use "--custom-resource-mode=true" in your CIS Configuration).

### 4. Install the Nginx Ingress Controller.

* Refer to [Integration with F5 Container Ingress Services](https://docs.nginx.com/nginx-ingress-controller/installation/integrations/f5-ingresslink/) to deploy NGINX Ingress Controller.

### 5. Create an IngressLink Resource.

* Download the sample IngressLink Resource:

  ```curl -OL https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/cis-3.x/config_examples/customResource/IngressLink/ingresslink.yaml```

* Update the "virtualServerAddress" parameter in the ingresslink.yaml resource. This IP address will be used to configure the BIG-IP device. It will be used to accept traffic and load balance it among the NGINX Ingress Controller pods.

  ```kubectl apply -f ingresslink.yaml```

##### Note:
1. The name of the app label selector in IngressLink resource should match the labels of the service which exposes the NGINX Ingress Controller.
2. The service which exposes the NGINX Ingress Controller should be of type ``nodeport``.

### 6. Test the Integration.

To test the integration, deploy a sample application:

    kubectl apply -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/cis-3.x/config_examples/customResource/IngressLink/ingress-example/cafe.yaml
    kubectl apply -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/cis-3.x/config_examples/customResource/IngressLink/ingress-example/cafe-secret.yaml
    kubectl apply -f https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/cis-3.x/config_examples/customResource/IngressLink/ingress-example/cafe-ingress.yaml

The Ingress Controller pods are behind the IP configured in Step 5 (virtualServerAddress parameter).

To test the traffic (in this example we used 192.168.10.5 as our VirtualServerAddress):

    $ curl --resolve cafe.example.com:443:192.168.10.5 https://cafe.example.com:443/coffee --insecure
    Server address: 10.12.0.18:80
    Server name: coffee-7586895968-r26zn
    ...

If you check the status of the cafe-ingress, you will see the IP of the VirtualServerAddress (in this example we used 192.168.10.5 as our VirtualServerAddress):
```
$ kubectl get ing cafe-ingress
NAME           HOSTS              ADDRESS         PORTS     AGE
cafe-ingress   cafe.example.com   192.168.10.5    80, 443   115s
```
