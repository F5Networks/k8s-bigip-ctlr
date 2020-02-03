# Helm Chart for the F5 BIG-IP Controller

This chart simplifies repeatable, versioned deployment of the [F5 BIG-IP Controller for Kubernetes](http://clouddocs.f5.com/products/connectors/k8s-bigip-ctlr/latest/).

### Prerequisites
- Add your BIG-IP device to your [Kubernetes](http://clouddocs.f5.com/containers/latest/kubernetes/kctlr-use-bigip-k8s.html) or [OpenShift](http://clouddocs.f5.com/containers/v2/openshift/kctlr-use-bigip-openshift.html) Cluster.
- Create a partition on your BIG-IP device for the BIG-IP Controller to manage. The Controller cannot manage objects in the `/Common` partition.
- Create a Secret containing the BIG-IP login credentials for the Controller. The Controller needs an account with administrator-level permissions to ensure full functionality.

The chart contains the following default values for partition and Secret, respectively:
- `f5-bigip-ctlr` and 
- `f5-bigip-ctlr-login` 

Be sure to change these if they differ from your actual partition and Secret names, using `--set <param>=<value>` or `-f <values-file.yaml>` as appropriate. See [customizing the chart before installing](https://docs.helm.sh/using_helm/#customizing-the-chart-before-installing) for more details.

## Chart Details

The chart creates a Deployment for one Pod containing the [k8s-bigip-ctlr](http://clouddocs.f5.com/products/connectors/k8s-bigip-ctlr/latest/) and its supporting RBAC resources.

## Installing the Chart

Run the commands shown below to install the chart using the default values.

```
helm repo add f5-stable https://f5networks.github.io/charts/stable
helm install --set args.bigip_url=1.2.3.4 f5-stable/f5-bigip-ctlr
```

Or

```
# from fork
helm install --set args.bigip_url=1.2.3.4 charts/src/stable/f5-bigip-ctlr
```

## Chart parameters:

> **Note:** Helm value names cannot include the character `-` which is commonly used in the names of parameters passed to the controller. To accomodate Helm, the parameter names in `values.yaml` use `_` and then replace them with `-` when rendering.
> e.g. `args.bigip_url` is rendered as `bigip-url` as required by the Controler.


Parameter | Description | Default
----------|-------------|--------
bigip_login_secret | Secret that contains BIG-IP login credentials | f5-bigip-ctlr-login
serviceaccount | name of ServiceAccount the ctlr will use | f5-bigip-ctlr-serviceaccount
args.bigip_url | The management IP for your BIG-IP device | **Required**, no default
args.partition | BIG-IP partition the ctlr will manage | f5-bigip-ctlr
args.log_level | Log detail | DEBUG for incubation chart
args.verify_interval | Interval, in seconds, at which to verify BIG-IP settings | Default is 30
args.node_poll_interval | Interval, in seconds, at which to poll the cluster | Default is 30

See the Controller documentation for a full list of [configuration parameters](http://clouddocs.f5.com/products/connectors/k8s-bigip-ctlr/latest/#controller-configuration-parameters).

If you have a specific use case for F5 products in the Kubernetes environment that would benefit from a curated chart, please [open an issue](https://github.com/F5Networks/charts/issues) describing your use case and providing example resources.

