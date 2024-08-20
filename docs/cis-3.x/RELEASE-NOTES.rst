Release Notes for Container Ingress Services for Kubernetes & OpenShift
=======================================================================

Next Release
-------------
Added Functionality
```````````````````
**What's new:**
    * Support for CIS deployment parameter "ipam-namespace" to configure the namespace for IPAM CR
    * Operator support for OpenShift
    * Helm chart support

3.0.0-beta-2
-------------

Added Functionality
```````````````````
**What's new:**
    * Support for Controller status in Deploy config CR
    * Support for CM and BIGIP Next v20.2.1
    * Support for ClusterIP mode using static routes with OVNKubernetes.
    * Support for OpenShift version 4.x

Bug Fixes
````````````
* Fix for IPAM CR cleanup issue
* Fix to handle invalid IPAM label and hostGroup combinations
* Fix for concurrent map access
* Fix deployConfigCR status update
* Fix L3Network task endpoint

3.0.0-beta
-------------

Added Functionality
```````````````````
**What's new:**
    * Support for Central Manager and BigIP-Next
    * Support for following resources:
        * Transport Server CR
        * Service Type Load balancer
        * IngressLink CR
        * Integration with FIC
    * Support for Nodeport Mode
