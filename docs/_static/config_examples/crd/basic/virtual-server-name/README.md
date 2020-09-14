# Custom Virtual Server Name

This section demonstrates the option to configure virtual server name. This is optional to use.
CRD allows the user to create a custom name for the virtual servers on BIG-IP.


Option which can be used to configure is :
    virtualServerName

## cusotm-virtual-name.yml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP as 
"<virtual server name>_<virtual server port>"
Ex. "cafe_virtual_server_80"

This is optional to use. Default name for virtual server created on BIG-IP as
"crd_<virtual IP address>_<virtual server port>"
Ex. "crd_172_16_3_4_80"