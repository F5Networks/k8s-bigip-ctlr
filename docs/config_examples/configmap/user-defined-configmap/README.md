# Container Ingress Services using AS3 Declarative API
This README.md demonstrates how CIS take advantage of a declarative API to configure and update BIG-IP from a kubernetes cluster.

## Example Use Cases

Examples demonstrates the following BIG-IP capabilities 

* HTTP, HTTPS 
* Cookie persistence
* TLS termination
* End to end TLS termination
* Web Application firewall
* Tenant filtering

## Declarative API

The Application Services 3 Extension uses a declarative model, meaning CIS sends a declaration file using a single Rest API call. An AS3 declaration describes the desired configuration of an Application Delivery Controller (ADC) such as F5 BIG-IP in tenant- and application-oriented terms. An AS3 tenant comprises a collection of AS3 applications and related resources responsive to a particular authority (the AS3 tenant becomes a partition on the BIG-IP system). An AS3 application comprises a collection of ADC resources relating to a particular network-based business application or system. AS3 declarations may also include resources shared by Applications in one Tenant or all Tenants as well as auxiliary resources of different kinds.

## Prerequisites for using AS3
CIS uses AS3 declarative API. We need the AS3 extension installed on BIGIP. 

From CIS > 2.0, AS3 >= 3.18 is required.
 
* Install AS3 on BIGIP
  https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/installation.html

* Get the required YAML files for the repo and update the files to the setup environment.
  https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/configmap/user-defined-configmap for YAML files to use moving forward.

CIS uses the partition defined in the CIS configuration by default to communicate with the F5 BIG-IP when adding static ARPs and forwarding entries for VXLAN. CIS managed partitions **<partition_AS3>** and **<partition>** should not be used in ConfigMap as Tenants. If CIS is deployed with **bigip-partition=cis**, then **<cis_AS3>** and **<cis>** are not supposed to be used as a tenant in AS3 declaration. Below is a proper declaration which would be correctly processed by CIS. Using **<k8s>** for the AS3 tenant in AS3. 

```
kind: ConfigMap
apiVersion: v1
metadata:
  name: f5-as3-declaration
  namespace: default
  labels:
    f5type: virtual-server
    as3: "true"
data:
  template: |
    {
        "class": "AS3",
        "declaration": {
            "class": "ADC",
            "schemaVersion": "3.13.0",
            "id": "urn:uuid:33045210-3ab8-4636-9b2a-c98d22ab915d",
            "label": "http",
            "remark": "A1 Template",
            "k8s": {
                "class": "Tenant",
                "A1": {
                    "class": "Application",
                    "template": "generic",
                    "a1_80_vs": {
                        "class": "Service_HTTP",
                        "remark": "a1",
                        "virtualAddresses": [
                            "10.192.75.101"
                        ],
                        "pool": "web_pool"
                    },
                    "web_pool": {
                        "class": "Pool",
                        "monitors": [
                            "http"
                        ],
                        "members": [
                            {
                                "servicePort": 8080,
                                "serverAddresses": []
                            }
                        ]
                    }
                }
            }
        }
    }
```

## Installing AS3 and handling SSL certificate verification 

* Install the AS3 RPM on the F5 BIG-IP. Following the link https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/installation.html
* If the F5 BIG-IP is using un-signed default ssl certificates add **insecure=true** as shown below to the CIS deployment yaml file.
    ```
    args: [
        "--bigip-username=$(BIGIP_USERNAME)",
        "--bigip-password=$(BIGIP_PASSWORD)",
        "--bigip-url=192.168.200.98",
        "--bigip-partition=AS3",
        "--namespace=default",
        "--pool-member-type=cluster",
        "--flannel-name=fl-vxlan",
        "--log-level=INFO",
        "--insecure=true",
    ```
* Add label as3:true in configMap metadata to any configmap applied so that CIS knows the data fields is AS3 and not legacy container connector input data. Please note that CIS will use gojsonschema to validate the AS3 data. If the declaration doesn't conform with the schema an error will be logged.
    ```
    metadata:
    name: f5-hello-world-https
    namespace: default
    labels:
        f5type: virtual-server
        as3: "true"
    ```
* Create and deploy the kuberenetes service discovery labels. CIS can dynamically discover and update load balancing pool members using service discovery. CIS maps each pool definition in the AS3 template to a Kubernetes Service resource using a label. To create this mapping, add the following labels to your Kubernetes Service.
    ```
    labels:
        app: f5-hello-world-end-to-end-ssl
        cis.f5.com/as3-tenant: AS3
        cis.f5.com/as3-app: A5
        cis.f5.com/as3-pool: secure_ssl_waf_pool
    name: f5-hello-world-end-to-end-ssl-waf
    ```
## Using a configmap with AS3
When using CIS with AS3 the behaviours are different The following needs to apply:

* CIS create one JSON declaration 
* Service doesn't matter on the order inside the declaration 
* Deleting a configmap doesn't remove the AS3 declaration and it associated partitions in BIG-IP.
* When adding new services use the kubectl apply command

