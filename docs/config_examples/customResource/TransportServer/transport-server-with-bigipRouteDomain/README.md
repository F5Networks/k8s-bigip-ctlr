# Transport Server with BigipRouteDomain

This section demonstrates the option to configure transport server using virtual server address with bigip route domain. This is optional to use.

Option which can be used to configure is :
    `bigipRouteDomain`

## transport-with-bigipRouteDomain.yaml

By deploying this yaml file in your cluster, CIS will create a Transport Server on BIG-IP with virtual server address and then route domain is appended.

This is optional to use. We can use `ipamLabel` with `bigipRoueDomain` parameter as well.