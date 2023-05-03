# Virtual Server with Multiple VIP

This section demonstrates the option to configure virtual server using additionalVirtualServerAddresses to create virtual servers listening on different VIP with same configuration.
This is optional to use.This feature uses AS3 virtualAddresses param which takes list of virtualServerAddresses to create virtual server listening to each IP address in list 


Option which can be used to configure is :
`additionalVirtualServerAddresses`

## virtual-with-multiplevip.yaml

By deploying this yaml file in your cluster, CIS will create two Virtual Servers on BIG-IP with vip "10.8.0.4" and "10.16.0.4".

### BIGIP-Config:

![multiplevipconfig](mvip-out.png?raw=true "BIGIP config")