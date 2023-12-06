# ipam-cluster-label Support

This section demonstrates the option to configure --ipam-cluster-label in CIS deployment.
ipam-cluster-label is supported for CRD resources with Infoblox IPAM Provider only and hence this feature is not supported on CRD resources without IPAM infoblox as the provider.
* Option which can be used to configure --ipam-cluster-label:

```
--ipam-cluster-label=cluster1
```
* By default --ipam-cluster-label is empty
* --ipam-cluster-label is prepended to the key to form the key for Infoblox IPAM provider.
* --ipam-cluster-label is used to identify the cluster in a multi-cluster environment.
* Allowed --ipam-cluster-label type is string

```Note: --ipam-cluster-label is supported for CRD resources with Infoblox IPAM Provider only```

```
Note: Remove the ipam CR created by previous version of CIS before enabling this --ipam-cluster-label parameter```
eg: kubectl -n kube-system delete ipam <CIS_deployment_name>.<CIS_managed_bigip_partition>.ipam
```

###### UseCase for --ipam-cluster-label deployment parameter
```
UseCase:
Github #https://github.com/F5Networks/k8s-bigip-ctlr/issues/3160
This deployment parameter is used to faciliate different IPaddresses for the same services/config existing in different clusters pointing out to the same infoblox NetView.
It is used to identify the cluster in a multi-cluster environment.

```

