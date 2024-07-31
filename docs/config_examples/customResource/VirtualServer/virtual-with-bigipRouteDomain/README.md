# Virtual Server with bigipRouteDomain

This section demonstrates the option to configure virtual server using virtual server with bigipRouteDomain. This is optional to use.

Option which can be used to configure is :
    `bigipRouteDomain`

## virtual-with-bigipRouteDomain.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with virtual server address and then route domain is appended.

This is optional to use. We can use `ipamLabel` with `bigipRoueDomain` parameter as well.