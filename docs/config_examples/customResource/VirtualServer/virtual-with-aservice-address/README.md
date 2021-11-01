# Virtual Service Address

This section demonstrates the option to configure virtual address with service address. This is optional to use.
Virtual server address can also be replaced by a reference to a Service_Address.
CRD allows the user to create a service address for virtual servers on BIG-IP.


Option which can be used to configure is :
    serviceAddress

## example-service-address-with-virtual.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server with service address on BIG-IP as 
"crd_service_address_<virtual address>"
Ex. "crd_service_address_172_16_3_9"
