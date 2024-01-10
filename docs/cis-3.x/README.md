Overview
========

The CIS controller is deployed as a Kubernetes deployment. The deployment creates a pod that runs the CIS controller. The controller watches for changes to Kubernetes objects and updates the BIG-IP accordingly.


Prerequisites
------------------
* Kubernetes 1.28+
* BigIP 20.0+
* Git
* kubectl

Installing CIS 3.x
------------------

Step 1: Clone the CIS repo

```shell
git clone https://github.com/F5Networks/k8s-bigip-ctlr.git
````
Step 2: Install the RBAC for CIS Controller

```shell
kubectl create -f ./docs/cis-3.x/rbac/clusterrole.yaml
```

Step 3: Install Custom Resource Definitions for CIS Controller

```shell
kubectl create -f ./docs/config_examples/customResourceDefinitions/incubator/customresourcedefinitions.yml
```

Step 4: Install CIS Deploy config CR

```shell
kubectl create -f ./docs/cis-3.x/cis-deploy-config-cr.yaml
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

Prometheus Metrics
------------------

| Name                                     | Type  | Default Status | Description                                                               | Labels                                   |
|------------------------------------------|-------|----------------|---------------------------------------------------------------------------|------------------------------------------|
| k8s_bigip_ctlr_managed_services          | Gauge | Enabled        | The total number of managed services by the CIS Controller                | -                                        |
| k8s_bigip_ctlr_managed_transport_servers | Gauge | Enabled        | The total number of managed transport servers by the CIS Controller       | -                                        |
| k8s_bigip_ctlr_configuration_warnings    | Gauge | Enabled        | The total number of configuration warnings by the CIS Controller          | ["kind" ,"namespace", "name", "warning"] |
| k8s_bigip_ctlr_managed_bigips            | Gauge | Enabled        | The total number of bigips where the CIS Controller posts the declaration | -                                        |
| k8s_bigip_ctlr_monitored_nodes           | Gauge | Enabled        | The total number of monitored nodes by the CIS Controller                 | ["nodeselector"]                         |
