# Virtual Server with IPAM Label

This section demonstrates the option to configure virtual server using IPAM label to manage the virtual server address. This is optional to use.
CRD allows the user manage the virtual server addresss using the F5 IPAM controller.


Option which can be used to configure is :
    `ipamLabel`

## virtual-with-ipam-label.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with virtual server address provided by IPAM controller.

This is optional to use. We can use `virtualServerAddress` parameter as well.