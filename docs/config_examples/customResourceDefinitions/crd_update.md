## What are CRDs?

Defining a CRD object allows creation of new custom resources with a specified name and schema. A CRD is a YAML file with kind `CustomResourceDefinition`.
The resources that use a CRD are custom resources. These custom resources have the apiVersion set to appropriate CRD.

Custom resources can appear and disappear in a running cluster through dynamic registration, and cluster admins can update custom resources independently of the cluster itself. Once a custom resource is installed, users can create and access its objects using kubectl, just as they do for built-in resources like Pods.

## Installation

* Install F5 CRDs
  - Install the F5 CRDs using following Commands:
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

## Updating Custom Resource Definitions

Currently, all 2.x.x releases support v1 version of CRDs. 

Below are changes which need attention. Please refer [release notes](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/RELEASE-NOTES.rst), [upgrade documentation](https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/upgradeProcess.md) for complete details.

| Version    | Change                                                                      |
|------------|-----------------------------------------------------------------------------|
| CIS 2.7.0  | Renamed EDNS resource name from **externaldnss** to **externaldns**         |
| FIC 0.1.5  | Renamed IPAM resource name from **f5ipam** CRD to **ipam**                  |
| CIS 2.13.0 | schema change for http2 profile in policy CRD from **string** to **object** |

Below steps are applicable for updating CRDs regardless of CIS installation method (manually or via helm or operator).

### Before an update 

* Take a backup of existing CustomResources which is planned for upgrade.
```sh
kubectl get vs -A -o yaml > vs_backup.yaml
kubectl get ts -A -o yaml > ts_backup.yaml
kubectl get tls -A -o yaml > tls_backup.yaml
kubectl get edns -A -o yaml > edns_backup.yaml
kubectl get il -A -o yaml > il_backup.yaml
kubectl get plc -A -o yaml > plc_backup.yaml
```

### During an update

* If new CRD adds support for extra fields, then existing configuration will not be impacted. 
  * Eg: `allowVlan` support in VS, TS from CIS release version 2.3.0. This is not a breaking change and hence existing resource configuration will not break.
* If CRD modifies existing field names, taking a backup of existing CustomResources will be helpful to modify the names.
  * Eg: Renaming EDNS resource name  
  Eg: If you are updating your EDNS CRD,
  ```sh
  kubectl get edns -A -o yaml > edns_backup.yaml
  ```
* For CIS version >= 2.13.0, If you are using http2 profile in the policy CR update the http2 profile from string to object as follows:
  ```yaml
  #Before update 
  http2: /Common/http2
  ```
  
  ```yaml
  #After Update 
  http2:
    client: /Common/http2
  ```
**Note**: If Policy CR is not updated with the latest schema CIS will not process the policy CR for any resource. 

### After an update

* Recreate the resources from the backup file if needed. 
```sh
kubectl create -f vs_backup.yaml
kubectl create -f ts_backup.yaml
kubectl create -f tls_backup.yaml
kubectl create -f edns_backup.yaml
kubectl create -f il_backup.yaml
kubectl create -f plc_backup.yaml
```
* Verify whether resources are reflected on BIG-IP and perform a traffic test to ensure end to end connectivity

## General troubleshooting

If a CRD is not found, then below log appears in CIS logs.

Eg: If a TransportServer CRD is not found,
```shell
E0412 10:59:47.965255 1 reflector.go:138] github.com/F5Networks/k8s-bigip-ctlr/pkg/controller/informers.go:75: Failed to watch *v1.TransportServer: failed to list *v1.TransportServer: the server could not find the requested resource (get transportservers.cis.f5.com)
```