#IngressLink with IPAM Label and BigipRouteDomain

This section demonstrates the option to configure ingressLink using IPAM label and BigipRouteDomain to manage the virtual server address. These are optional to use.
CRD allows the user manage the virtual server addresss using the F5 IPAM controller.


Option which can be used to configure is :
    `ipamLabel`
    `bigipRouteDomain`

## ingresslink-with-ipamLabel-bigipRouteDomain.yaml

By deploying this yaml file in your cluster, CIS will create a IngressLink on BIG-IP with virtual server address provided by IPAM controller and then appending the route domain to the generated virtual server address.

This is optional to use. We can use `virtualServerAddress` with `bigipRoueDomain` parameter as well.