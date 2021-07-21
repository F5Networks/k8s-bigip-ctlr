# Helm Chart for Managing Ingress Resources with a BIG-IP Device

This chart simplifies repeatable, versioned use of the [F5 BIG-IP Controller as an Ingress Controller](http://clouddocs.f5.com/containers/latest/kubernetes/kctlr-k8s-ingress-ctlr.html) in Kubernetes or OpenShift. 

### Prereqisites

- Install [Helm with Tiller](https://docs.helm.sh/using_helm/#installing-helm) on your cluster with appropriate permissions.
- Deploy the F5 BIG-IP Controller in your cluster. You can use the [f5-bigip-ctlr chart](https://github.com/F5Networks/charts/tree/master/src/stable/f5-bigip-ctlr) to deploy the Controller or you can deploy it [manually](http://clouddocs.f5.com/containers/latest/kubernetes/kctlr-app-install.html). 
- Deploy the Pods/Services accepting traffic from the Ingress.

> **Note:** This chart and the [f5-bigip-controller](https://github.com/recursivelycurious/charts/tree/wip/src/stable/f5-bigip-ctlr) chart can be used *independently or together*.  
> If you or your organization author your own charts either or both may be used as a [subchart](https://docs.helm.sh/chart_template_guide/#creating-a-subchart).
>
> Similarly, this Ingress chart can be combined -- either as a parent chart or a subchart -- with charts that define the services accepting traffic.

## Chart Details

The chart creates an Ingress resource for use with the [k8s-bigip-ctlr](http://clouddocs.f5.com/containers/latest/kubernetes/index.html).

## Installing the Chart

1. Copy the `values.yaml` file. Use this file as the basis for your own Ingress specification. 
2. Pass your custom values file when running `helm install` as shown in the example below.

```
helm repo add f5-stable https://f5networks.github.io/charts/stable
helm install -f path/to/custom-values.yaml f5-stable/f5-bigip-ingress
```

Or

```
# from fork
helm install -f path/to/custom-values.yaml charts/src/stable/f5-bigip-ingress/
```

## Primary Chart parameters:

Parameter | Description | Default
----------|-------------|--------
ingress.annotations.virtual-server.f5.com/ip | IP accepting traffic on the BIG-IP device | **Required** no default
ingress.annotations.virtual-server.f5.com/partition | BIG-IP partition of the Controller | **Required** no default
ingress.namespace | Kubernetes/OpenShift namespace for the Ingress | Optional
spec | Backend(s) and associated hosts and paths | See [examples](https://github.com/F5Networks/charts/tree/master/example_values/f5-bigip-ingress) 

### Additional Optional parameters as Annotations

The Annotations listed under the `ingress.annotations` parameter are consumed as an array and any of the [documentend Annotations for the k8s-bigip-ctlr](http://clouddocs.f5.com/products/connectors/k8s-bigip-ctlr/latest/#supported-ingress-annotations) may be used.

When using the `virtual-server.f5.com/health` Annotation the value must be a JSON array of the individual health monitors. Single and multiple health monitor examples can be seen in the [Ingress Examples](https://github.com/F5Networks/charts/tree/master/example_values) in this repo.

> CAUTION: Be sure to use the correct version of the Controller for the Annotations you wish to use. See the [k8s-bigip-ctlr release notes](http://clouddocs.f5.com/products/connectors/k8s-bigip-ctlr/latest/RELEASE-NOTES.html) for more information.

If you have a specific use case for F5 products in the Kubernetes environment that would benefit from a curated chart, please [open an issue](https://github.com/F5Networks/charts/issues) describing your use case and providing example resources.

