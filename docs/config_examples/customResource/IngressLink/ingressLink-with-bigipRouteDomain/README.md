#IngressLink with BigipRouteDomain

This section demonstrates the option to configure the  virtual server address with bigipRouteDomain. This is optional to use.

Option which can be used to configure is :
    `bigipRouteDomain`

## ingresslink-with-bigipRouteDomain.yaml

By deploying this yaml file in your cluster, CIS will create a IngressLink on BIG-IP with virtual server address and then route domain is appended.

This is optional to use. We can use `ipamLabel` with `bigipRoueDomain` parameter as well.