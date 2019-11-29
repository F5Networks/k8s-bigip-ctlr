Release Notes for BIG-IP Controller for Kubernetes
==================================================

Next Release
------------
Added Functionality
`````````````````````
* Controller handles extended URL paths to the nearest matching backend context paths.
* Support AS3 for BIG-IP orchestration with Kubernetes Ingress.
* Controller implements support for overriding already existing AS3 resources(ConfigMap, Route and Ingress) through ConfigMap. 

Bug Fixes
`````````
* Controller handles combination of Edge and Reencrypt Openshift routes.
* Controller now does not send encrypted traffic to backend.
* Controller now does not log dozens of "INFO" log messages frequently in CCCL mode.
* Ingress in K8S cluster mode, observing no data plane traffic as there were no static ARP entries available in BIG-IP.

Limitations
```````````
* Master Node label must set to "node-role.kubernetes.io/master=true" when operating on K8S version 1.13.4 or OSCP version 4.1 in nodeport mode. If not set, BIG-IP treats master node as any other pool member.

v1.11.1
------------
Bug Fixes
`````````
* Controller handles WAF Policy in the root path of a domain in OpenShift Routes.
* Controller handles OpenShift Routes with WAF Policy in multiple namespaces.
* Controller now does not push configuration to BigIP using AS3 for every 30 seconds with no changes.
* :issues:`1041` Controller now does not log dozens of "INFO" log messages frequently.
* :issues:`1040` Controller does not crashes if latest AS3 schema is not available.
* Controller updates Route Status in OpenShift Management Console (OCP 4.x)
* Controller does not crash when handling Route with WAF Policy that does not have a service.


v1.11.0
------------
Added Functionality
`````````````````````
* Added support for WAF policy reference through ``virtual-server.f5.com/waf`` annotation in OpenShift Routes.
* Added support for OpenShift version 4.1.
    - | Controller service account needs ``cluster-admin`` role. Before upgrading controller to v1.11.0 and above, update cluster role as follows:
      | ``oc adm policy add-cluster-role-to-user cluster-admin -z <service-account-name> -n <namespace>``
* Added support for Alternate Backend Deployment in OpenShift Routes while using as3 backend. 
* Controller updates Route status in Openshift Web Console (OpenShift 3.11 and below).
* Controller includes the body of AS3 API call error responses in Debug logs.
* Added support for validating AS3 JSON against the latest schema. Controller downloads the latest schema during startup.

Bug Fixes
`````````
* :issues:`790` Controller properly handles OpenShift path based routes with TLS.
* :issues:`1016` Controller now logs INFO messages to STDOUT instead of STDERR.
* Controller provides readable help message in logs when ``--router-vserver-addr`` is not configured.

Limitations
```````````
* Limitations for Openshift Routes orchestration through AS3 backend are available `here <https://clouddocs.f5.com/containers/latest/openshift/kctlr-use-as3-backend.html>`_.

v1.10.0
------------
Added Functionality
`````````````````````
* Changed container base image from debian-stretch to debian-buster.
* Support AS3 for BIG-IP orchestration with Openshift Routes using `--agent=as3` option.
* Support disabling Ingress resource processing using `--manage-ingress` option.
* Controller does not use master node as a pool member when marked as unscheduled in NodePort Mode.
* Support BIG-IP 14.x when using AS3 Orchestration for BIG-IP in Openshift.

Bug Fixes
`````````
* Controller adds pods in unscheduled nodes as pool members.
* Controller now handles Openshift route TLS termination switch from reencrypt to edge.

Limitations
```````````
* Limitations for Openshift Routes orchestration through AS3 backend are available `here <https://clouddocs.f5.com/containers/latest/openshift/kctlr-use-as3-backend.html>`_.

v1.9.2
------------
Bug Fixes
`````````
* Controller handles http redirects without entering into an infinite loop.
* :issues:`810` Controller does not delete resources in BIG-IP and recreates during controller pod restart.

v1.9.1
------
Added Functionality
`````````````````````
* Added support for `establishing trust <https://clouddocs.f5.com/containers/v2/kubernetes/kctlr-as3-cert-trust.html>`_ with remote BIG-IP systems using either the device or CA certificates.
* Added support for AS3 3.11.

Bug Fixes
`````````
* Improves performance when updating Configmaps with AS3 Declarations.
* Improves performance when updating Services associated with AS3 Declarations.
* Improves performance when handling changes in Endpoints associated with AS3 Declarations.
* Improves performance when handling node updates in AS3 Declarations.
* Improves performance when applying AS3 Declarations to BIG-IP.
* :issues:`797` - Controller uses ``flannel.alpha.coreos.com/public-ip`` as VTEP endpoint.

Vulnerability Fixes
```````````````````
+------------------+----------------------------------------------------------------+
| CVE              | Comments                                                       |
+==================+================================================================+
| CVE-2019-6648    | Controller no longer prints AS3 Declarations in debug logs     |
+------------------+----------------------------------------------------------------+

v1.9.0
------------

Added Functionality
```````````````````
* Added support for `Application Services 3 Extension <https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/>`_.
* Added support for Google Container Engine (GKE) LoadBalancer service. Validated against Kubernetes 1.13.4.

Bug Fixes
`````````
* :issues:`736` - Added support for Google Container Engine (GKE) LoadBalancer service. Validated against Kubernetes 1.13.4.

Limitations
```````````
* AS3 pool class declarations support only one load balancing pool.
* The BIG-IP Contoller supports only one AS3 ConfigMap instance.
* AS3 does not support moving BIG-IP nodes to new partitions.
* Static ARP entries remain after deleting an AS3 ConfigMap.

v1.8.1
------

Bug Fixes
`````````
* Fixes security vulnerabilities between Controller and BIG-IP.

  - CVE-2017-18342
  - CVE-2018-100807
  - CVE-2018-18074

v1.8.0
------

Added Functionality
```````````````````
* Added support for Services handling in namespaces of Kubernetes and Openshift that starts with a number.
* Validated against 14.X versions of BIG-IP

Bug Fixes
`````````
* :issues:`810` - Controller doesn't delete services and recreates during bigip-ctlr pod restart
* :issues:`718` - Namespaces that start with a number does not cause errors

Limitations
```````````
* Openshift Routes are not compatible with 14.X versions of BIG-IP

v1.7.1
------

Vulnerability Addresses
```````````````````````
+------------------+----------------------------------------------------------------+
| CVE              | Comments                                                       |
+==================+================================================================+
| CVE-2018-1002105 | Validated against Kubernetes 1.12.3                            |
+------------------+----------------------------------------------------------------+

Bug fixes
`````````
* :issues:`789` - Controller properly creates https redirect for child paths in k8s Ingress.
* Fixes an issue in openshift where communication breaks with clients with no SNI support.

v1.7.0
------

Added Functionality
```````````````````
* Added `--manage-configmaps` argument to CC to prevent or allow CC to respond to ConfigMap events. Defaults to `true`.
* Added `virtual-server.f5.com/whitelist-source-range` Ingress/Route annotation to support IP CIDR whitelisting.
* :issues:`699` - Ability to configure health monitor type in Ingress/Route annotation. Http is the default.
* Changed container base image to use debian-slim.

Bug Fixes
`````````
* :issues:`735` - Deleted rules from routes and ingresses on the same service not cleaned up properly.
* :issues:`753` - Controller doesn't delete and recreate annotation-based policy rules.
* :issues:`755` - Controller implements best-match by setting first-match and sorting rules in reverse lexical order.
* :issues:`765` - Controller properly sorts Route rules in reverse lexical order.

v1.6.1
------

Bug Fixes
`````````
* :issues:`486` - User cannot configure the controller to manage the Common partition.
* :issues:`743` - Controller doesn't temporarily remove entire BIG-IP configs after deleting a single service.
* :issues:`746` - Log messages and documentation added to ensure Route profile configuration is clear.

v1.6.0
------

Added Functionality
```````````````````
* VEL-1484: Added ability to provide BIG-IP credentials via mounted Secret files instead of CLI arguments.

Bug Fixes
`````````
* Improved controller performance when deep copying configurations.
* Improved controller performance when starting up and achieving "steady state".

Vulnerability Fixes
```````````````````
+-----------------------+---------------+----------------------------------------------------------------+----------------+
| ID Number             | CVE           | Solution Article(s)                                            | Description    |
+=======================+===============+================================================================+================+
| VEL-1484              | CVE-2018-5543 | `[#K58935003] <https://support.f5.com/csp/article/K58935003>`_ | CVE-2018-5543  |
+-----------------------+---------------+----------------------------------------------------------------+----------------+

v1.5.1
------

Bug Fixes
`````````
* :issues:`683` - Controller upgrades properly with new metadata field.
* :issues:`686` - Controller in cluster mode does not rely on vxlan name to configure pool members.

v1.5.0
------

Added Functionality
```````````````````
* Support for virtual server source address translation configuration.
* Support for app-root and url-rewrite annotations.
* Added controller name and version to the metadata of certain BIG-IP LTM resources managed by the controller.
* :issues:`433` - Support for pre-existing server ssl profiles for Ingresses.
* Added support for attaching OpenShift Routes to existing BIG-IP virtual servers.
* Added support for Kubernetes version 1.8.
* Added support for OpenShift Origin version 3.7.
* Added support for Red Hat OpenShift Container Platform (OSCP) version 3.7.
* (BETA) Added initial basic support for Prometheus metrics.
* `F5 IPAM Controller <https://github.com/F5Networks/f5-ipam-ctlr>`_ pairs with k8s-bigip-ctlr by writing out `virtual-server.f5.com/ip` annotation for IP addresses allocated for host names in Ingresses or ConfigMaps.
* Added support for using `helm`_ to deploy the Controller using the `f5-bigip-ctlr chart`_.
* Added support for using `helm`_ to deploy Ingress resources using the `f5-bigip-ingress chart`_.

Bug Fixes
`````````
* :issues:`552` - Controller properly creates Secret SSL profiles for ConfigMaps.
* :issues:`592` - Node label selector works properly in cluster mode.
* :issues:`603` - Pool only mode no longer prints excessive logs.
* :issues:`608` - Single service Ingresses cannot share virtual servers.
* :issues:`636` - Controller configures default ssl profiles for Routes when specified via CLI.
* :issues:`635` - Controller cleans up policy rules when an Ingress removes them.
* :issues:`638` - Ingress extended paths no longer break BIG-IP GUI links.
* :issues:`649` - Route annotation profiles are no longer ignored.
* :cccl-issue:`214` - Keys and certificates are now installed onto the managed partition.

Limitations
```````````
* Cannot apply app-root and url-rewrite annotations to the same resource; see: :issues:`675`
* If an older controller created resources, upgrading to the new version could
  result in a python exception when adding metadata to virtuals: :issues:`683`
* If running the controller in cluster mode without a vxlan name, pool members are not created: :issues:`686`

v1.4.2
------

Bug Fixes
`````````
* :issues:`549` - Using IP annotation on ConfigMaps would result in the virtual server getting a port of 0.
* :issues:`551` - Memory leak in python subprocess
* :cccl-issue:`211` - Memory leak in f5-cccl submodule
* :issues:`555` - Controller high CPU usage when inactive
* :issues:`510` - Change behavior of controller on startup when encountering errors
* :issues:`567` - Clean up all objects (including iRules and datagroups) when deleting Routes.

v1.4.1
------

Bug Fixes
`````````
* :issues:`517` - Controller deletes SSL profiles off of Ingress virtual servers if watching multiple namespaces.
* :issues:`471` - When updating routes, old service pools are not removed until after a refresh cycle.
* :cccl-issue:`208` - Address compatibility for BIG-IP v13.0 Health Monitor interval and timeout.

v1.4.0
------

Added Functionality
```````````````````
* Enhanced route domain handling:

  - Create VxLAN forwarding database (FDB) addresses for route domains.
  - Ability to change the default route domain for a partition managed by an F5 controller after the controller has deployed.

* Support for `Flannel VxLAN in Kubernetes`_.
* Enhanced options for configuring Virtual IP addresses for Ingress resources:

  - Ingresses with the same IP address and port can share a virtual server.
  - Set a default IP address to use as the VIP for all Ingresses.

* Support for ``recv`` strings in health monitors for ConfigMaps, Ingresses, and Routes.
* Support UDP in ConfigMaps (includes proxy type and health monitors).
* Provide Controller version info in the container and logs.
* Support for ``virtual-server.f5.com/balance`` annotation for Routes.
* Support for A/B deployments using the Openshift route alternateBackends token.

Bug Fixes
`````````
* :issues:`341` - HTTPS redirect applies to individual Routes instead of all Routes.
* :issues:`344` - Create default for SNI profile when using Ingress custom profiles from Secrets.
* :issues:`460` - Remove risk that pools will update with wrong members after a node update (NodePort mode).
* :issues:`428` - Controller writes unnecessary updates when no config changes occurred.
* :issues:`506` - Controller stops updating BIG-IP after an exception occurs in the python driver.
* :cccl-issue:`198` - Corrected a comparison problem in CCCL that caused unnecessary updates for BIG-IP Virtual Server resources.

Limitations
```````````
* If you are deploying services using the F5-supported iApps, you must upgrade to a version that supports
  route domain 0 for non-Common partitions. The minimum versions required for the F5 iapps are:

  - f5.http: ``f5.http.v1.3.0rc3``
  - f5.tcp: ``f5.tcp.v1.0.0rc3``

  You can find these versions in the iapp package ``iapps-1.0.0.492.0``. To upgrade, you must perform the following:

  - `Download and install the latest iApps templates`_.
  - `Set the service to use the newer iApp template`_.

* Check BIG-IP version compatibility on Application Services (iApps) before deploying. See Application Services Integration iApp `[#16] <https://github.com/F5Networks/f5-application-services-integration-iApp/issues/16>`_ for more information.
* Cannot delete ARP entries on BIG-IP v11.6.1 when running the Controller in Kubernetes with Flannel VXLAN enabled.
* The controller will exit at startup if it cannot establish a connection with the BIG-IP.

v1.3.0
------

Added Functionality
```````````````````

* Create health monitors for OpenShift Routes via an annotation.
* Optionally disable loading of certificates and keys from Routes in preference of using pre-existing
  profiles on the BIG-IP system.
* Optionally disable loading of Kubernetes Secrets on an Ingress.
* Resolve the first host name in an Ingress to an IP address using a local or custom DNS server. The controller
  configures the virtual server with this address.
* Support for BIG-IP partitions with non-zero default route domains.

Bug Fixes
`````````
* OpenShift Route targetPort field is no longer required if the port is not 80 or 443.
* Properly configure named targetPorts in OpenShift Route configurations.
* Remove ssl certificate lists for deleted custom profiles.

Limitations
```````````

* If a Route configuration contains no targetPort, the controller uses the first port it sees
  on the referenced Service. The controller does not use all ports.
* You cannot change the default route domain for a partition managed by an F5 controller after the controller has deployed. To specify a new default route domain, use a different partition.

v1.2.0
------

Added Functionality
```````````````````

* Introduced support for Kubernetes 1.6 and 1.7.
* Watch all nodes by default; watch a subset of nodes with a user-specified label.
* Create BIG-IP SSL Profiles from Kubernetes Secrets via Ingress TLS.
* Create BIG-IP objects from OpenShift Route resources.
  - This includes unsecured, edge, passthrough, and re-encrypt Routes.

* This is a feature-complete upgrade from the OpenShift F5Router.
  See `Replace the OpenShift F5 Router with the BIG-IP Controller <http://clouddocs.f5.com/containers/latest/openshift/replace-f5-router.html>`_ for more information.

Bug Fixes
`````````
* Properly configure http redirect rules on v11.6.1 BIG-IP systems.
* Failed configurations for objects do not prevent future configurations from happening.

Limitations
```````````

* OpenShift - Does not currently support redirect for individual Routes. If a Route specifies
  "insecureEdgeTerminationPolicy" as "Redirect", the http virtual server will enable this policy for all Routes.
  `[#341] <https://github.com/F5Networks/k8s-bigip-ctlr/issues/341>`_

v1.1.1
------

Bug Fixes
`````````
* Fix SIGSEV on non-"f5" valued class annotation `[#311] <https://github.com/F5Networks/k8s-bigip-ctlr/issues/311>`_
* Remove default pool for Ingress and Routes `[#288] <https://github.com/F5Networks/k8s-bigip-ctlr/issues/288>`_

v1.1.0
------

Added Functionality
```````````````````

* Creation of BIG-IP Virtual Servers from Kubernetes Ingress resources.
* Configure multiple SSL Profiles for a BIG-IP Virtual Server.
* Watch all Kubernetes namespaces by default; watch a list of namespaces; watch namespaces with a user-specified label.
* Watch for Kubernetes annotation if virtual address not specified, enabling custom IPAM integration.
* Create detached pools if virtual server bind addresses not specified.
* Container image size reduced from 361MB to 123MB.
* Can use local and non-local BIG-IP users.

Limitations
```````````

* The SSL Profiles referenced in Ingress resources must already exist on the BIG-IP device.
  Any Secret resources configured in Kubernetes are not used.

v1.0.0
------

Added Functionality
```````````````````

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

Limitations
```````````

* Cannot share endpoints managed in a partition controlled by the K8S BIG-IP Controller with endpoints managed in another partition.
* Kubernetes allows a service to name the individual service ports within a particular service.  However, the K8S BIG-IP Controller requires the virtual server section within the configmap to refer to the port number for the service port, not the name.
* Two virtual servers cannot point to the same servicePort.  The last one specified will be the one that remains configured.
* The BIG-IP Controller does not handle non-zero route domains.  All managed partitions should use the default route domain (0).
* Parameters other than IPAddress and Port (e.g. Connection Limit) specified in the iApp Pool Member Table apply to all members of the pool.
* Cannot configure virtual servers with IPv6 addresses in the configmap.
* The K8S BIG-IP Controller cannot watch more than one namespace.


.. _Download and install the latest iApps templates: https://support.f5.com/csp/article/K13422
.. _Set the service to use the newer iApp template: https://support.f5.com/csp/article/K17001
