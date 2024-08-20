Overview
========

The CIS controller is deployed as a Kubernetes deployment. The deployment creates a pod that runs the CIS controller. The controller watches for changes to Kubernetes objects and updates the BIG-IP accordingly.

Compatibility Matrix
--------------------

| CIS Version | CIS Chart Version | CIS operator Version | BIG-IP Version | Kubernetes Version | OpenShift Version | OVN | FIC Version | FIC Chart Version | FIC Operator Version | OS Version                                  |
|-------------|-------------------|----------------------|----------------|--------------------|-------------------|-----|-------------|-------------------|----------------------|---------------------------------------------|
| v3.0.0      | v3.0.0            | v3.0.0               | v20.0-v20.3    | v1.28-v1.31        | v4.12-v4.16       | Yes | v0.1.10     | v0.0.5            | v0.0.6               | Red Hat Enterprise Linux release 9.1 (Plow) |

Prerequisites
------------------
* Kubernetes 1.28+
* BigIP 20.0+
* Git
* kubectl

Installing CIS 3.x Using Helm Charts
------------------------------------

Refer to [CIS Helm Charts](https://f5networks.github.io/k8s-bigip-ctlr/helm-charts/)

Installing CIS 3.x Manually
---------------------------

Step 1: Clone the CIS repo

```shell
git clone https://github.com/F5Networks/k8s-bigip-ctlr.git
````
Step 2: Install the RBAC for CIS Controller

```shell
cd k8s-bigip-ctlr
kubectl create -f ./docs/cis-3.x/rbac/clusterrole.yaml
```

Step 3: Install Custom Resource Definitions for CIS Controller

```shell
kubectl create -f ./docs/config_examples/customResourceDefinitions/incubator/customresourcedefinitions.yml
```

Step 4: Update the deploy config CR with the required parameters and create the deploy config CR

```shell
kubectl create -f ./docs/cis-3.x/deploy-config/cis-deploy-config-cr.yaml
```

Step 5: Create the kubernetes secret for Central Manager credentials

```shell
mkdir "creds"
echo -n "admin" > creds/username
echo -n "admin" > creds/password
echo -n "10.10.10.10" > creds/url
kubectl create secret generic f5-bigip-ctlr-login -n kube-system --from-file=creds/ 
```

Step 6: Update the CIS deployment file (./docs/cis-3.x/install/k8s/sample-k8s-bigip-ctlr.yaml) with required image and parameters and install the CIS Controller.

```shell
kubectl create -f ./docs/cis-3.x/install/k8s/sample-k8s-bigip-ctlr.yaml
```

Uninstalling CIS 3.x
--------------------

To uninstall CIS 3.x, run the following commands:

```shell
kubectl delete -f ./docs/cis-3.x/install/k8s/sample-k8s-bigip-ctlr.yaml
kubectl delete secret f5-bigip-ctlr-login -n kube-system
kubectl delete -f ./docs/config_examples/customResourceDefinitions/incubator/customresourcedefinitions.yml
kubectl delete -f ./docs/cis-3.x/rbac/clusterrole.yaml
```

Configuration Parameters
------------------------
All the configuration parameters below are global.

### General
| Parameter            | Type      | Required  | Default         | Description                                                                                     | Allowed Values | Minimum Supported Version |
|----------------------|-----------|-----------|-----------------|-------------------------------------------------------------------------------------------------|----------------|---------------------------|
| http-listen-address	 | String	   | Optional	 | “0.0.0.0:8080”	 | Address at which to serve HTTP-based information (for example, /metrics, health) to Prometheus. |                |                           |
| version              | 	Boolean	 | Optional  | 	false          | 	Print CIS version.                                                                             | true, false    |                           |
| disable-teems        | 	Boolean	 | Optional  | 	false          | If true, disable sending telemetry data to TEEM                                                 | true, false    |                           |
| deploy-config-cr	    | String    | Required  | N/A             | 	Specify a CRD that holds additional spec for controller                                        |                |                           |

### Logging
| Parameter | Type    | Required  | Default | Description                      | Allowed Values                                 | Minimum Supported Version |
|-----------|---------|-----------|---------|----------------------------------|------------------------------------------------|---------------------------|
| log-level | 	String | 	Optional | 	INFO   | 	Log level	                      | INFO, DEBUG, AS3DEBUG CRITICAL, WARNING, ERROR |                           |
| log-file	 | String  | Optional  | 	N/A	   | File path to store the CIS logs. |                                                |                           |

**Note**: AS3DEBUG should only be used for debugging purposes, as it may impact CIS performance. 


### CentralManager system
| Parameter             | Type    | Required  | Default | Description                                                                                                                                                                                                                     | Allowed Values                                                                       | Minimum Supported Version |
|-----------------------|---------|-----------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|---------------------------|
| cm-password           | String  | Required  | 	N/A    | CentralManager password for the user account <br/> You can secure your CentralManager credentials using a Kubernetes Secret.                                                                                                    |                                                                                      |                           |
| cm-url                | 	String | 	Required | 	N/A    | CentralManager URL <br> Examples: <br> URL with non-standard port --cm-url= https://x.x.x.x:8443 <br> IP address --cm-url= x.x.x.x <br> IP address with port --cm-url= x.x.x.x:8080 <br> IPv6 address --cm-url= '[2001:db8::6]' | IP address <br> URL:PORT <br> IP-addr:PORT <br> For IPv6 address as string inside [] |                           | |
| cm-username           | String  | Required  | 	N/A    | CentralManager username for the user account                                                                                                                                                                                    |                                                                                      |                           |
| credentials-directory | String  | Optional  | N/A     | Directory that contains the CentralManager username, password, or url files.                                                                                                                                                    |                                                                                      |                           |
| no-verify-ssl         | Boolean | Optional  | false   | When set to true, enable insecure SSL communication to CentralManager.                                                                                                                                                          | true, false                                                                          |                           |
| trusted-certs-cfgmap  | String  | Required  | N/A     | When certificates are provided, adds them to controller trusted certificate store.                                                                                                                                              |                                                                                      |                           |


### Important
````
The credentials-directory option is an alternative to using the cm-username, cm-password, or cm-url arguments.

When you use this argument, the controller looks for three files in the specified directory:

“username”, “password”, and “url”
If any of these files do not exist, the controller falls back to using the CLI arguments as parameters.

Each file should contain only the username, password, and url, respectively. You can create and mount the files as Kubernetes Secrets.

It is important to not project the Secret keys to specific paths, as the controller looks for the “username”, “password”, and “url” files directly within the credentials directory.

````

### Kubernetes
| Parameter               | Type    | Required  | Default     | Description                                                                     | Allowed Values | Minimum Supported Version |
|-------------------------|---------|-----------|-------------|---------------------------------------------------------------------------------|----------------|---------------------------|
| kubeconfig              | String  | 	Optional | 	./config   | Path to the kubeconfig file                                                     |                |                           |
| manage-custom-resources | Boolean | 	Optional | 	true       | 	Specify whether or not to manage custom resources i.e. transport server        | 	true, false   |                           |
| use-node-internal       | Boolean | Optional  | true        | filter Kubernetes InternalIP addresses for pool members	                        | true, false    |                           |
| ipam                    | Boolean | Optional  | false       | Specify if CIS provides the ability to interface with F5 IPAM Controller (FIC)	 | true, false    |                           |
| ipam-namespace          | String  | Optional  | kube-system | Specify the namespace of ipam custom resource	                                  | true, false    |                           |


Prometheus Metrics
------------------

| Name                                     | Type  | Default Status | Description                                                               | Labels                                   |
|------------------------------------------|-------|----------------|---------------------------------------------------------------------------|------------------------------------------|
| k8s_bigip_ctlr_managed_services          | Gauge | Enabled        | The total number of managed services by the CIS Controller                | -                                        |
| k8s_bigip_ctlr_managed_transport_servers | Gauge | Enabled        | The total number of managed transport servers by the CIS Controller       | -                                        |
| k8s_bigip_ctlr_configuration_warnings    | Gauge | Enabled        | The total number of configuration warnings by the CIS Controller          | ["kind" ,"namespace", "name", "warning"] |
| k8s_bigip_ctlr_managed_bigips            | Gauge | Enabled        | The total number of bigips where the CIS Controller posts the declaration | -                                        |
| k8s_bigip_ctlr_monitored_nodes           | Gauge | Enabled        | The total number of monitored nodes by the CIS Controller                 | ["nodeselector"]                         |


## Recommendations
* Never change the controllerIdentifier parameter in the deploy config CR for a CIS instance. ControllerIdentifier is a unique identifier for the CIS instance. CIS uses it for uniquely creating static routes configured on Big-IP Next. Changing it may render some static routes out of sync in case CIS is running in staticRoutingMode.

