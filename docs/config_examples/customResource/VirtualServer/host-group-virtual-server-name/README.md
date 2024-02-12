# Custom Host Group Virtual Server Name

This section demonstrates the option to configure virtual server name when hostGroup is present across multiple Virtual Servers. This is optional to use.
CRD allows the user to create a custom name for the virtual servers on BIG-IP when hostGroupVirtualServerName is provided along with hostGroup.


Option which can be used to configure is :
    hostGroupVirtualServerName

## vs-with-hostGroup-hostGroupVirtualServerName.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP as
"<host group virtual server name>_<virtual server port>"
Ex. "cafe_virtual_server_80"

This is optional to use. Default name for virtual server created on BIG-IP as
"crd_<virtual IP address>_<virtual server port>"
Ex. "crd_172_16_3_4_80"

The yaml **vs-ts-with-hostGroup-hostGroupVirtualServerName.yaml** will have the same behaviour as above after applying.
