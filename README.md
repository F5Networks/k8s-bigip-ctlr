
[![Build Status](https://dev.azure.com/f5networks/CIS/_apis/build/status/F5Networks.k8s-bigip-ctlr?branchName=master) ](https://dev.azure.com/f5networks/CIS/_build/latest?definitionId=6&branchName=master)
[![Coverage Status](https://coveralls.io/repos/github/F5Networks/k8s-bigip-ctlr/badge.svg) ](https://coveralls.io/github/F5Networks/k8s-bigip-ctlr)

**AS OF April 2026, THIS GITHUB REPOSITORY WILL NO LONGER BE MONITORED OR UPDATED.**
 
This repository will remain available, at least temporarily. You can find the latest releases in [RH Container registry](https://catalog.redhat.com/en/software/containers/f5networks/cntr-ingress-svcs/5ec7ad05ecb5246c0903f4cf). Refer to 'Filing Issues and Getting Help' for additional details.

F5 BIG-IP Container Ingress Services for Kubernetes & OpenShift
========================================================

The F5 BIG-IP Container Ingress Services for [Kubernetes](https://kubernetes.io/) and [OpenShift](https://www.openshift.com/) makes F5 [BIG-IP](https://www.f5.com/products/big-ip-services) services available to applications running in Kubernetes and OpenShift.

Documentation
-------------

For instruction on how to use this component, see the
[docs](https://clouddocs.f5.com/containers/latest/)
for F5 BIG-IP Container Ingress Services for Kubernetes & OpenShift.

For guides on this and other solutions for Kubernetes, see the
[F5 Solution Guides for Kubernetes](https://clouddocs.f5.com/containers/latest/userguide/kubernetes/).

What's New?
-----------
Support for Custom Resource Definitions [Documentation](./docs/config_examples/customResource/CustomResource.md)

Getting Help
------------

We encourage you to use the cis-kubernetes channel in our [f5CloudSolutions Slack workspace](https://f5cloudsolutions.slack.com/)  for discussion and assistance on this
controller. This channel is typically monitored Monday-Friday 9am-5pm MST by F5
employees who will offer best-effort support.

Contact F5 Technical support via your typical method for more time sensitive
changes and other issues requiring immediate support.


Running
-------

The official docker image is `f5networks/k8s-bigip-ctlr`.

Usually, the controller is deployed in Kubernetes. However, the controller can be run locally for development testing.

```shell
docker run f5networks/k8s-bigip-ctlr /app/bin/k8s-bigip-ctlr <args>
```

## Filing Issues and Getting Help
If you encounter a bug or other issue while using F5 CIS, use [F5 Technical Support](https://www.f5.com/support) to submit it to our team.
 
**Important**: As of April 2026, GitHub issues are no longer being monitored by F5 support staff.
