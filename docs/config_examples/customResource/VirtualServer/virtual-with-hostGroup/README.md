# Virtual Server with Host Group

This section demonstrates the option to configure virtual server using Host Group to club virtual servers with different host names into one in BIG-IP. 
This is optional to use. Hostgroup label should be unique across namespaces as hostgroup can also be used to group virtualservers from different namespaces into one in BIGIP.


Option which can be used to configure is :
    `hostGroup`

## virtual-with-hostGroup.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with virtual servers having same hostGroup.

This is optional to use. We need to use `virtualServerAddress` or `ipamLabel` parameter with same value in all virtual servers .

## vs-ts-with-hostGroup.yaml (Host Group with TransportServer and VirtualServer CRs)

This section demonstrates the option to configure Transport server using Host Group to leverage the IPAM allocated VIP for VirtualServer CR in TransportServer CR.
This is optional to use. Hostgroup label makes the possibility of leveraging the same VIP of TransportServer CR to VirtualServer CR and vice-versa