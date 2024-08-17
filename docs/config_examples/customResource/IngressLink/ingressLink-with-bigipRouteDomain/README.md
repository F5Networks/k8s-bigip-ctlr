#IngressLink with BigipRouteDomain

This section demonstrates the option to configure the  virtual server address with bigipRouteDomain. This is optional to use and is not supported in Cluster pool member type.

Option which can be used to configure is :
    `bigipRouteDomain`

## ingresslink-rd-with-vsAddress.yaml

By deploying this yaml file in your cluster, CIS will create a IngressLink on BIG-IP with virtual server address and then route domain is appended.

## ingresslink-rd-with-ipamLabel.yaml

By deploying this yaml file in your cluster, CIS will create a IngressLink on BIG-IP with virtual server address fetched from the ipam as per the ipamLabel and then route domain is appended.

**Note:**
    - In nodeport pool member type, route domains should be created in Common shared partition as the nodes will be shared across the other virtual servers of BigIP.
