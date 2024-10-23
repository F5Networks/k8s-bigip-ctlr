# Helm Chart for the F5 Container Ingress Services

This chart simplifies repeatable, versioned deployment of the [Container Ingress Services](https://clouddocs.f5.com/containers/latest/).

### Prerequisites
- Refer to [CIS Prerequisites](https://clouddocs.f5.com/containers/latest/userguide/cis-helm.html#prerequisites) to install Container Ingress Services on Kubernetes or Openshift
- [Helm 3](https://helm.sh/docs/intro/) should be installed.


## Installing CIS Using Helm Charts

This is the simplest way to install the CIS on OpenShift/Kubernetes cluster. Helm is a package manager for Kubernetes. Helm is Kubernetes version of yum or apt. Helm deploys something called charts, which you can think of as a packaged application. It is a collection of all your versioned, pre-configured application resources which can be deployed as one unit. This chart creates a Deployment for one Pod containing the [k8s-bigip-ctlr](https://clouddocs.f5.com/containers/latest/), it's supporting RBAC, Service Account and Custom Resources Definition installations.

## Installing the Chart

- (Optional) Add Central Manager credentials as K8S secrets.

For Kubernetes, use the following command:

```kubectl create secret generic f5-bigip-ctlr-login -n kube-system --from-literal=username=admin --from-literal=password=<password>```
    
For OpenShift, use the following command:

```oc create secret generic f5-bigip-ctlr-login -n kube-system --from-literal=username=admin --from-literal=password=<password>```
    
- Add the CIS chart repository in Helm using following command:

```helm repo add f5-stable https://f5networks.github.io/k8s-bigip-ctlr/helm-charts/stable```
    
- Create values.yaml as shown in [examples](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/helm-charts/example_values/values.yaml):

- Install the Helm chart if Central Manager credential secrets created manually using the following command:
  
```helm install -f values.yaml <new-chart-name> f5-stable/f5-bigip-ctlr```

- Install the Helm chart with skip crds if Central Manager credential secrets created manually (without custom resource definitions installations)

```helm install --skip-crds -f values.yaml <new-chart-name> f5-stable/f5-bigip-ctlr```

- If you want to create the Central Manager credential secret with helm charts use the following command:

```helm install --set cm_secret.create="true" --set cm_secret.username=$CM_USERNAME --set cm_secret.password=$CM_PASSWORD -f values.yaml <new-chart-name> f5-stable/f5-bigip-ctlr```
    
## Chart parameters:

| Parameter                                             | Required | Description                                                                                                           | Default                      |
|-------------------------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------|------------------------------|
| cm_login_secret                                       | Optional | Secret that contains Central Manager login credentials                                                                | f5-bigip-ctlr-login          |
| args.cm_url                                           | Required | The management IP for your Central Manager device                                                                     | **Required**, no default     |
| cm_secret.create                                      | Optional | Create kubernetes secret using username and password                                                                  | false                        |
| cm_secret.username                                    | Optional | Central Manager username to create the kubernetes secret                                                              | empty                        |
| cm_secret.password                                    | Optional | Central Manager password to create the kubernetes secret                                                              | empty                        |
| rbac.create                                           | Optional | Create ClusterRole and ClusterRoleBinding                                                                             | true                         |
| serviceAccount.name                                   | Optional | name of the ServiceAccount for CIS controller                                                                         | f5-bigip-ctlr-serviceaccount |
| serviceAccount.create                                 | Optional | Create service account for the CIS controller                                                                         | true                         |
| namespace                                             | Optional | name of namespace CIS will use to create deployment and other resources                                               | kube-system                  |
| image.user                                            | Optional | CIS Controller image repository username                                                                              | f5networks                   |
| image.repo                                            | Optional | CIS Controller image repository name                                                                                  | k8s-bigip-ctlr               |
| image.pullPolicy                                      | Optional | CIS Controller image pull policy                                                                                      | Always                       |
| image.pullSecrets                                     | Optional | List of secrets of container registry to pull image                                                                   | empty                        |
| version                                               | Optional | CIS Controller image tag                                                                                              | latest                       |
| nodeSelector                                          | Optional | dictionary of Node selector labels                                                                                    | empty                        |
| tolerations                                           | Optional | Array of labels                                                                                                       | empty                        |
| limits_cpu                                            | Optional | CPU limits for the pod                                                                                                | 100m                         |
| limits_memory                                         | Optional | Memory limits for the pod                                                                                             | 512Mi                        |
| requests_cpu                                          | Optional | CPU request for the pod                                                                                               | 100m                         |
| requests_memory                                       | Optional | Memory request for the pod                                                                                            | 512Mi                        |
| affinity                                              | Optional | Dictionary of affinity                                                                                                | empty                        |
| securityContext                                       | Optional | Dictionary of deployment securityContext                                                                              | empty                        |
| podSecurityContext                                    | Optional | Dictionary of pod securityContext                                                                                     | empty                        |
| deployConfig.baseConfig.controllerIdentifier          | Optional | controllerIdentifier is used to identify the unique CIS cluster/instance                                              | empty                        |
| deployConfig.baseConfig.nodeLabel                     | Optional | nodeLabel is used to define the nodes which can be monitored by CIS                                                   | empty                        |
| deployConfig.baseConfig.namespaceLabel                | Optional | namespaceLabel is used to define the namespces which can be monitored by CIS                                          | empty                        |
| deployConfig.networkConfig.orchestrationCNI           | Required | Orchestration CNI for the kuberentes/openshift cluster                                                                | empty                        |
| deployConfig.networkConfig.metaData.poolMemberType    | Optional | poolMemberType is optional parameter, and it is used to specify the pool member type in CIS default value is nodeport | nodeport                     |
| deployConfig.networkConfig.metaData.networkCIDR       | Optional | network CIDR is optional parameter and required if your nodes are using multiple network interfaces                   | empty                        |
| deployConfig.networkConfig.metaData.staticRoutingMode | Optional | staticRoutingMode creates the static routes for pod network on the BigIP                                              | false                        |
| deployConfig.as3Config.debugAS3                       | Optional | debugAS3 is a optional parameter, and it is used to enable the debug logs for AS3                                     | false                        |
| deployConfig.as3Config.postDelayAS3                   | Optional | post delay is a optional parameter, and it is used if AS3 is taking more time to apply the configuration              | 0                            |
| deployConfig.bigIpConfig[*].bigIpAddress              | Required | Big IP to deploy the application                                                                                      | empty                        |
| deployConfig.bigIpConfig[*].bigIpLabel                | Required | bigIpLabel is used to map the ingress resource to the bigip, you can specify the bigip label in TS/IngressLink CR     | empty                        |
| deployConfig.bigIpConfig[*].defaultPartition          | Optional | Big IP tenant                                                                                                         | 0                            |


Note: cm_login_secret and cm_secret are mutually exclusive, if both are defined in values.yaml file cm_secret will be given priority.


See the CIS documentation for a full list of args supported for CIS [CIS Configuration Options](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/cis-20.x/README.md#configuration-parameters)

> **Note:** Helm value names cannot include the character `-` which is commonly used in the names of parameters passed to the controller. To accomodate Helm, the parameter names in `values.yaml` use `_` and then replace them with `-` when rendering.
> e.g. `args.cm_url` is rendered as `cm-url` as required by the CIS Controller.


If you have a specific use case for F5 products in the Kubernetes environment that would benefit from a curated chart, please [open an issue](https://github.com/F5Networks/k8s-bigip-ctlr/issues) describing your use case and providing example resources.

## Uninstalling Helm Chart

Run the following command to uninstall the chart.

```helm uninstall <new-chart-name>```

