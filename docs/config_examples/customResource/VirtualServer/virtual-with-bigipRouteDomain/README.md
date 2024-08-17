# Virtual Server with bigipRouteDomain

This section demonstrates the option to configure virtual server using virtual server with bigipRouteDomain. This is optional to use and is not supported in Cluster pool member type.

Option which can be used to configure is :
    `bigipRouteDomain`

## virtual-rd-with-vsAddress.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with virtual server address and then route domain is appended.

## virtual-rd-with-ipamLabel.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with virtual server address fetched from the ipam as per the ipamLabel and then route domain is appended.

**Note:**
    - In nodeport pool member type, route domains should be created in Common shared partition as the nodes will be shared across the other virtual servers of BigIP.
