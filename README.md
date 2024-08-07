# F5 Networks Helm Charts

This repository contains [helm](https://docs.helm.sh/using_helm/#using) charts for use with some [F5 Networks](https://f5.com/) products and services within a [Kubernetes](https://kubernetes.io/) or [OpenShift](https://www.openshift.com/) environment.

**Note:** Charts may require access to `kube-system` namespace and/or cluster wide permissions for full functionality. Be sure to install/configure helm/tiller appropriately.

## Stable Charts

The stable directory contains charts that are created/curated and tested by F5 Networks. These charts are supported by F5 Networks (see [SUPPORT](./SUPPORT.md) for details).

To add the stable repo to helm:

```
helm repo add f5-stable https://f5networks.github.io/k8s-bigip-ctlr/helm-charts/stable
```

Stable Charts:
- [f5-bigip-ctlr](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/src/stable/f5-bigip-ctlr) - Use this chart to deploy the [k8s-bigip-ctlr](https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/cis-3.x/README.md) in Kubernetes or OpenShift.

## Documentation

Each chart has a README describing its basic functionality. The `values.yaml` file for each chart shows the default values and links to documentation for the resources the chart deploys.

## Incubation Charts

The incubation charts may have been created by F5 Networks or by external contributors. These charts have not undergone full testing and are subject to change. F5 Networks does not provide technical support for templates in the incubation directory.

To access additional charts in a development or testing mode that may not be documented:

```
helm repo add f5-incubator https://f5networks.github.io/k8s-bigip-ctlr/helm-charts/incubator
```
