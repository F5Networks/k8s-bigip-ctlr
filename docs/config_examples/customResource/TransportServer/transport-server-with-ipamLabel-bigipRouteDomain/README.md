# Transport Server with IPAM Label and BigipRouteDomain

This section demonstrates the option to configure transport server using IPAM label and Bigip Route Domain to manage the virtual server address. This is optional to use.
CRD allows the user manage the virtual server addresss using the F5 IPAM controller.


Option which can be used to configure is :
    `ipamLabel`
    `bigipRouteDomain`

## transport-with-ipam-label-bigipRouteDomain.yaml

By deploying this yaml file in your cluster, CIS will create a Transport Server on BIG-IP with virtual server address provided by IPAM controller and then appending the route domain to the generated virtual server address.

This is optional to use. We can use `virtualServerAddress` parameter with bigipRouteDomain as well.