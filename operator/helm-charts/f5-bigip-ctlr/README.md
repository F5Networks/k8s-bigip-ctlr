# Helm Chart for the F5 Container Ingress Services

This chart simplifies repeatable, versioned deployment of the [Container Ingress Services](https://clouddocs.f5.com/containers/latest/).

### Prerequisites
- Refer to [CIS Prerequisites](https://clouddocs.f5.com/containers/latest/userguide/cis-helm.html#prerequisites) to install Container Ingress Services on Kubernetes or Openshift
- [Helm 3](https://helm.sh/docs/intro/) should be installed.


## Installing CIS Using Helm Charts

This is the simplest way to install the CIS on OpenShift/Kubernetes cluster. Helm is a package manager for Kubernetes. Helm is Kubernetes version of yum or apt. Helm deploys something called charts, which you can think of as a packaged application. It is a collection of all your versioned, pre-configured application resources which can be deployed as one unit. This chart creates a Deployment for one Pod containing the [k8s-bigip-ctlr](https://clouddocs.f5.com/containers/latest/), it's supporting RBAC, Service Account and Custom Resources Definition installations.

## Installing the Chart

- Add BIG-IP credentials as K8S secrets.

For Kubernetes, use the following command:

```kubectl create secret generic f5-bigip-ctlr-login -n kube-system --from-literal=username=admin --from-literal=password=<password>```
    
For OpenShift, use the following command:

```oc create secret generic f5-bigip-ctlr-login -n kube-system --from-literal=username=admin --from-literal=password=<password>```
    
- Add the CIS chart repository in Helm using following command:

```helm repo add f5-stable https://f5networks.github.io/charts/stable```
    
- Create values.yaml as shown in [examples](https://github.com/F5Networks/charts/tree/master/example_values/f5-bigip-ctlr):

- Install the Helm chart using the following command:
  
```helm install -f values.yaml <new-chart-name> f5-stable/f5-bigip-ctlr```

- Install the Helm chart with skip crds (without custom resource definitions installations)

```helm install --skip-crds -f values.yaml <new-chart-name> f5-stable/f5-bigip-ctlr```
    
## Chart parameters:

Parameter | Required | Description | Default    
----------|-------------|-------------|--------
bigip_login_secret | Required |  Secret that contains BIG-IP login credentials | f5-bigip-ctlr-login
args.bigip_url | Required | The management IP for your BIG-IP device | **Required**, no default
args.partition | Required | BIG-IP partition the CIS Controller will manage | f5-bigip-ctlr
args.namespaces | Optional | List of Kubernetes namespaces which CIS will monitor | empty
rbac.create | Optional | Create ClusterRole and ClusterRoleBinding | true
serviceAccount.name | Optional | name of the ServiceAccount for CIS controller | f5-bigip-ctlr-serviceaccount
serviceAccount.create | Optional | Create service account for the CIS controller | true
namespace | Optional | name of namespace CIS will use to create deployment and other resources | kube-system
image.user | Optional | CIS Controller image repository username | f5networks
image.repo | Optional | CIS Controller image repository name | k8s-bigip-ctlr
image.pullPolicy | Optional | CIS Controller image pull policy | Always
version | Optional | CIS Controller image tag | latest
nodeSelector | Optional | dictionary of Node selector labels | empty
tolerations | Optional | Array of labels | empty
limits_cpu | Optional | CPU limits for the pod | 100m
limits_memory | Optional | Memory limits for the pod | 512Mi
requests_cpu | Optional | CPU request for the pod | 100m
requests_memory | Optional | Memory request for the pod | 512Mi
affinity | Optional | Dictionary of affinity | empty
securityContext | Optional | Dictionary of securityContext | empty





See the CIS documentation for a full list of args supported for CIS [CIS Configuration Options](https://clouddocs.f5.com/containers/latest/userguide/config-parameters.html)

> **Note:** Helm value names cannot include the character `-` which is commonly used in the names of parameters passed to the controller. To accomodate Helm, the parameter names in `values.yaml` use `_` and then replace them with `-` when rendering.
> e.g. `args.bigip_url` is rendered as `bigip-url` as required by the CIS Controller.


If you have a specific use case for F5 products in the Kubernetes environment that would benefit from a curated chart, please [open an issue](https://github.com/F5Networks/charts/issues) describing your use case and providing example resources.

## Uninstalling Helm Chart

Run the following command to uninstall the chart.

```helm uninstall <new-chart-name>```

