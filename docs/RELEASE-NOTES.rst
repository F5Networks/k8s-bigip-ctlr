Release Notes for K8S BIG-IP Controller
============================================

v1.1.0-dev
----------

* Features

  * Watches all Kubernetes namespaces by default, or can watch a list of namespaces, or namespaces with a customer specified label. This addresses a previous limitation in v1.0.0.
  * Watches for Kubernetes annotation if virtual address not specified, enabling custom IPAM integration.
  * Creates detached pools if virtual server bind addresses not specified.
  * Container image size reduced from 361MB to 123MB.
  * Can use local and non-local BIG-IP users.

v1.0.0
------

* Capabilities

  * Can manage multiple BIG-IP partitions in the following environments

    * Kubernetes
    * Red Hat OpenShift 

  * Manages the following LTM resources for the BIG-IP partition(s)

    * Virtual Servers
    * Virtual Addresses
    * Pools
    * Pool Members
    * Nodes
    * Health Monitors
    * Application Services

  * Manages the following Network resource for the BIG-IP partition(s)
  
    * FDB tunnel records (Red Hat OpenShift)

* Limitations

  * Cannot share endpoints managed in a partition controlled by the K8S BIG-IP Controller with endpoints managed in another partition.
  * Kubernetes allows a service to name the individual service ports within a particular service.  However, the K8S BIG-IP Controller requires the virtual server section within the configmap to refer to the port number for the service port, not the name.
  * Two virtual servers cannot point to the same servicePort.  The last one specified will be the one that remains configured.
  * The BIG-IP Controller does not handle non-zero route domains.  All managed partitions should use the default route domain (0).
  * Parameters other than IPAddress and Port (e.g. Connection Limit) specified in the iApp Pool Member Table apply to all members of the pool.
  * Cannot configure virtual servers with IPv6 addresses in the configmap.
  * The K8S BIG-IP Controller cannot watch more than one namespace.

