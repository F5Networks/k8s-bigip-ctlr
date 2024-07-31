# Virtual Server with IPAM Label and bigipRouteDomain

This section demonstrates the option to configure virtual server using IPAM label and bigipRouteDomain to manage the virtual server address. This is optional to use.
CRD allows the user manage the virtual server addresss using the F5 IPAM controller.


Option which can be used to configure is :
    `ipamLabel`
    `bigipRouteDomain`

## virtual-with-ipam-label-bigipRouteDomain.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with virtual server address provided by IPAM controller and then appended with the route domain to the generated virtual server address.

This is optional to use. We can use `virtualServerAddress` with `bigipRoueDomain` parameter as well.