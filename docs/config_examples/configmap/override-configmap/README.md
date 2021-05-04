# Container Ingress Services using AS3 Override Declaration
AS3 override functionality allows you to alter the existing Big-IP configuration using AS3 with a Override configmap without affecting the existing Kubernetes resources. The administrator can modify the existing BIG-IP configuration incrementally without having to overwrite/delete the existing one.

Use AS3 override when you want to manually create a virtual server in a CIS managed partition In order to do this you will need to add a new argument to the deployment file.

## Configuring Override AS3 in CIS 
* Add the following deployment parameter to enable AS3 override functionality in CIS:

`--override-as3-declaration=<namespace>/<user_defined_configmap_name>`


    args: [
        "--bigip-username=$(BIGIP_USERNAME)",
        "--bigip-password=$(BIGIP_PASSWORD)",
        "--bigip-url=192.168.200.98",
        "--bigip-partition=AS3",
        "--namespace=default",
        "--pool-member-type=cluster",
        "--flannel-name=fl-vxlan",
        "--log-level=INFO",
        "--override-as3-declaration=<namespace>/<override_as3_configmap_name>"
        "--insecure=true",
    

    Note: The <namespace> must be CIS managed namespace, from above example deployment, <namespace> must be "default". 

* Add label overrideAS3:true in configMap metadata to any override AS3 configmap applied so that CIS knows the data fields is override AS3 and not legacy container connector input data. Please note that CIS will use gojsonschema to validate the AS3 data.
 
    ```
    metadata:
    name: f5-hello-world-https
    namespace: default
    labels:
        f5type: virtual-server
        overrideAS3: "true"
    ```

