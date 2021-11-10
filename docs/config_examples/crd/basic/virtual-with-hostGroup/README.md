# Virtual Server with Host Group

This section demonstrates the option to configure virtual server using Host Group to club virtual servers with different host names into one in BIG-IP. 
This is optional to use.


Option which can be used to configure is :
    `hostGroup`

## virtual-with-hostGroup.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with virtual servers having same hostGroup.

This is optional to use. We need to use `virtualServerAddress` or `ipamLabel` parameter with same value in all virtual servers .