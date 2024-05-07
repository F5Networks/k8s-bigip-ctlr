# Transport Server with IPAM Label

This section demonstrates the option to configure transport server using IPAM label to manage the virtual server address. This is optional to use.
CRD allows the user manage the virtual server addresss using the F5 IPAM controller.


Option which can be used to configure is :
    `ipamLabel`

## transport-with-ipam-label.yaml

By deploying this yaml file in your cluster, CIS will create a Transport Server on BIG-IP with virtual server address provided by IPAM controller.

This is optional to use. We can use `virtualServerAddress` parameter as well.