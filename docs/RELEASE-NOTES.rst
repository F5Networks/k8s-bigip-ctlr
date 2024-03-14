Release Notes for Container Ingress Services for Kubernetes & OpenShift
=======================================================================

2.16.0
-------------

Added Functionality
```````````````````
**What's new:**
    * Multi Cluster
      * `Issue 3284 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3284>`_: Add support to avoid service pool creation for clusters under maintenance. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/multicluster/extendedConfigmap/>`_
      * Streamline the naming convention for extended service references and multi cluster references annotations.
        * See `Example with the updated field names for extendedServiceReferences in VS CRD: <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/multicluster/customResource/virtualServer/vs-with-extended-services.yaml>`_
        * See `Example the updated field names for multiClusterServices annotation in NextGenRoutes: <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/multicluster/routes/route-with-multicluster-service-annotation.yaml>`_
    * CRD
      * `Issue 3225 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3225>`_: Support for Host Persistence to configure and disable the Persistence in VS Policy Rule action based on host in VirtualServer. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResource/VirtualServer/virtual-server-with-hostPersistence/>`_
      * `Issue 3262 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3262>`_: Support for Host Aliases to allow defining multiple hosts in VS CRD. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResource/VirtualServer/virtual-with-hostAliases>`_.
      * `Issue 3263 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3263>`_: Support for Host group virtual server name in virtual server to customise the virtual server name when Host Group exists. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResource/VirtualServer/host-group-virtual-server-name>`_
      * `Issue 3279 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3279>`_: Support for disabling default partition in AS3 legacy nodeport mode.
      * `Issue 3295 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3295>`_: Support for setting the default pool via policy CRD for virtual server and nextgen routes. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResource/Policy>`_.
      * `Issue 3239 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3239>`_: Support for mix of k8s Secret and bigip reference in TLSProfile. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/VirtualServerWithTLSProfile/reencrypt-hybrid-reference>`_
      * Support for setting sslProfile with https monitor in virtualServer and nextgen routes.
        * See `Example for Virtual Server CRD <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResource/VirtualServerWithTLSProfile/tls-with-health-monitor/>`_
        * See `Example for NextGenRoutes <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/next-gen-routes/routes/route-with-target-port-health-monitor.yaml>`_
      * Support self value for SNAT in virtualServer and transportServer.
    * Support for pool-member-type auto for CRD, NextGen Routes and multiCluster mode. Please refer `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/PoolType-Auto/README.md>`_
    * Support for CIS deployment parameters "trusted-certs-cfgmap" && "insecure"  in CRD and NextGen. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/configmap/trusted-certs-configmap/>`_
    * CIS compatible with AS3 3.50

Bug Fixes
````````````
* `Issue 3230 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3230>`_: CRD multicluster configuration triggers Raw response from Big-IP: map[code:422 declarationFullId: message:declaration has duplicate values in rules]. Please refer FAQ in `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/multicluster/README.md>`_
* `Issue 3232 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3232>`_: Enhance as3 response add the runtime attribute.
* `Issue 3266 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3266>`_: Improve log when admitting next gen routes.
* `Issue 3267 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3267>`_: Improve log for certificate host name validation.
* `Issue 3268 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3268>`_: Handle embedded certificates appropriately when missing SAN and hostnames mismatch. 
* `Issue 3277 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3277>`_: Additional PoolMember properties in ConfigMap not preserved for NodePortLocal mode.
* `Issue 3299 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3299>`_: Fix for EDNS in AS3 and CCCL modes.
* `Issue 3312 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3312>`_: CIS 2.15 crashes due to interface conversion panic.
* Fix for wildcard domain with multiple hosts in tls profile.
* Improve documentation for HTTP2 profile. Please refer `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResource/VirtualServerWithTLSProfile/tls-with-http2-profile>`_


Upgrade notes
``````````````
* From this version, in CRD, the default value of "--insecure" will be false and if "trusted-certs-cfgmap" deployment parameter is not configured, CIS might crash with error "x509: certificate signed by unknown authority".
* From this version, in multicluster, **serviceName** replaced with **service** and **port** replaced with **servicePort** in the **extendedServiceReferences**.

2.15.1
-------------

Added Functionality
```````````````````
**What's new:**
    * CRD
        * Support for HTML profile in Policy CR and VirtualServer CR. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.15-stable/docs/config_examples/customResource/Policy/policy-with-html-profile.yaml>`
        * Support for renegotiationEnabled in TLSProfile CR. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.15-stable/docs/config_examples/customResource/VirtualServerWithTLSProfile/tls-with-ssl-renegotiation-disabled>`
    * CIS compatible with OpenShift 4.14 and Kubernetes 1.29
    * Improved operator support for OpenShift 4.14

Bug Fixes
````````````
* `Issue 3160 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3160>`_: Support to provide different IPs for the same resources deployed in different clusters for Infoblox IPAM provider only.
* `Issue 3197 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3197>`_: Image mismatch in F5 operator metadata.


2.15.0
-------------

Added Functionality
```````````````````
**What's new:**
    * Multi Cluster
        * Add support for cluster AdminState. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/multicluster/extendedConfigmap/global-spec-config-for-multicluster-with-cluster-admin-state.yaml>`_
    * Next Generation Routes
        * Moved from pod liveness probe based health monitor to readiness probe based health monitor for autoMonitor. See `DeploymentPod Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/next-gen-routes/deployment/deployment-pod-with-readinessprobe.yaml>`_, `AutoMonitor Example <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/configmap/extendedRouteConfigwithBaseConfigWithAutoMonitor.yaml>`_
        * Support for new route annotation **virtual-server.f5.com/pod-concurrent-connections**. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/next-gen-routes/routes/sample-route-with-pod-concurrent-connections-annotation.yaml>`_
    * CRD
       * `Issue 3062 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3062>`_: Support ConnectionMirroring in virtualserver and Transportserver CR. See `VirtualServerCR Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/2.x-master/docs/config_examples/customResource/VirtualServer/ConnectionMirroring/vs-with-connection-mirroring.yaml>`_, `TransportServerCR Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/TransportServer/ts-with-connection-mirroring.yaml>`_
       * `Issue 2963 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2963>`_: Support MinimumMonitors in virtualserver CR
    * `Issue 3066 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3066>`_: Support for a/b deployment custom persistence in CRD, nextGen routes with cluster mode. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/customResource/Policy/policy-with-ab-persistence.yaml>`_
    * Support for dedicated AS3 GTM agent for GTM Server
    * Support for new CIS health check endpoint /ready
    * Support for configuring node network CIDR for ovn-k8s CNI with staticRoutingMode. See `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/StaticRoute>`_
    * CIS compatible with OpenShift 4.13, Kubernetes 1.28 and AS3 3.48
    * Improved Operator support for OpenShift 4.13

Bug Fixes
````````````
* `Issue 3057 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3057>`_: Support for pool settings for reselect with policy CR.
* `Issue 3061 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3061>`_: Provide stable pool name in multi cluster mode
* `Issue 3079 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3079>`_: Fix logic for node not ready check
* `Issue 3073 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3073>`_: Fix AS3 config map multi port service issue
* `Issue 2985 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2985>`_: Improve CIS primary and secondary coordination
* `Issue 3126 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3126>`_: VirtualServer with hostGroup and ipamLabel set returns the wrong vsAddress status

Upgrade notes
``````````````
* Disabled default health monitoring with routes, use autoMonitor support for NextGenRoutes. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/tree/2.x-master/docs/config_examples/next-gen-routes/configmap/extendedRouteConfigwithBaseConfigWithAutoMonitor.yaml>`_

Known Issues
`````````````
*  [Multi-Cluster] Route status is not updated in other HA cluster.
*  `Issue 777 <https://github.com/F5Networks/f5-appsvcs-extension/issues/777>`_: Cluster adminState in multiCluster mode doesn't work properly with AS3 (v3.47 and v3.48) as updating pool member adminState from enable to offline fails with 422 error with AS3 (v3.47 and v3.48). If customer needs this feature, we recommend to use AS3 v3.46 or lower on BIGIP.

2.14.0
-------------

Added Functionality
```````````````````
**What's new:**
    * Multi Cluster support
        * Support for custom resources on openshift & kubernetes. See `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/multicluster>`_ for more details.
        * Support for routes on openshift. See `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/multicluster>`_ for more details.
    * Configmap
        * Support for AS3 logLevel parameter in configmap
        * Support for AS3 persist parameter in configmap
    * Ingress
        * Support for default pool using the single-service ingress
    * CRD
        * NodePortLocal mode support added with all custom resources
        * Support for default pool with VS CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/VirtualServer/defaultpool/>`_
        * Support for service typeLB in EDNS CR, See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/serviceTypeLB/service-type-lb-with-hostname.yaml>`_
        * Support for **persistence** capability for service published through EDNS.  See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/ExternalDNS/externaldns.yaml>`_
        * Support for wildcard domain in EDNS CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/ExternalDNS/externaldns-wildcard-domain.yaml>`_
        * Support for preferred client subnet in EDNS CR using AS3. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/ExternalDNS/externaldns-client-subnet-preferred.yaml>`_
        * Support for fallbackLbmode with EDNS CR See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/ExternalDNS/external-dns-with-lbModeFallback>`_
        * Support for wildcard domain name with passthrough termination
    * Helm Chart Enhancements
        * Support for latest CRD schema
    * New log level **AS3DEBUG** to log the AS3 request & response for AS3 mode
    * CIS is now compatible with BIG-IP 17.x

Bug Fixes
````````````
* CIS properly handles virtual server CRs with same IP address but different hostnames and traffic termination settings.
* `Issue 2785 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2785>`_: Support for wildcard domains in EDNS CR
* `Issue 2813 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2813>`_: Add EDNS support for service typeLB.
* `Issue 2850 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2850>`_: Fix for AS3 config updated every 30 seconds by CIS with default ingress backend
* `Issue 2909 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2909>`_: Fix for empty pool members when K8S API server throws any error
* `Issue 2941 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2941>`_: Fix for services with same name in different namespaces in NodePortLocal mode
* `Issue 2978 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2978>`_: Nodes in 'NotReady' state are not removed from their pool(s) when using ServiceType LoadBalancer
* `Issue 3004 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/3004>`_: ExternalDNS Global Availability Mode not working

Known Issues
`````````````
*  [Multi-Cluster] Pool members are not getting populated for extended service in ratio mode
*  [Multi-Cluster] CIS doesn't update pool members if service doesn't exist in primary cluster but exists in secondary cluster for Route.
*  [Multi-Cluster] CIS on start up in multiCluster mode, if any external cluster kube-api server is down/not reachable, CIS does not process any valid clusters config also.
*  [Multi-Cluster] CIS fails to post declaration intermittently with VS when using health monitors in ratio mode.


2.13.1
-------------
Bug Fixes
````````````
* Fix removal of static ARP entries for Flannel CNI during CIS restart
* `Issue 2800 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2800>`_: Fix monitor not creating for VS CRD when send string is missing
* `Issue 2867 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2867>`_: Ignore virtualServerName if hostGroup configured
* `Issue 2898 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2898>`_: Fix for CIS crash with namespace-label parameter
* `Issue 2778 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2778>`_: Fix for hostless VS does not work with IPAM
* `Issue 2908 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2908>`_: Fix for CIS crash while updating the route status
* `Issue 2912 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2912>`_: Enable metrics with ipv6 mode


2.13.0
-------------

Added Functionality
```````````````````
**What’s new:**
    * Next generation routes. See `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details.
        * Support for a separate policy CR for HTTP VS in NextGen Routes.
        * NextGen Route controller takes precedence over Legacy Route deployment parameters
    * CRD
        * Support webSocket Profile in Policy CR, See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/Policy/policy-with-websocket-profile.yaml>`_.
        * Support for server-side http2 profile using policy CR, See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/Policy/sample-policy.yaml>`_.
        * Support setting Auto-LastHop option from policy CR, See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/Policy/policy-with-autoLastHop.yaml>`_.
        * Support setting http mrf router option from policy CR (applied for HTTPS virtual server only), See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/Policy/policy-with-httpMrfRouter.yaml>`_.
        * Support for setting http analytics profile from policy CR, See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/Policy/policy-with-http-analytics-profile.yaml>`_.
        * Support for configuring multiple iRules with policyCR, See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/Policy/policy-with-multiple-irules.yaml>`_.
        * Support for setting client and server ssl profiles from policy CR for NextGen Routes only, See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/Policy/policy-with-client-server-ssl-profile.yaml>`_.
        * Support for AB deployment with VS CR, See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/VirtualServerWithTLSProfile/virtual-with-alternatebackends/virtual-with-ab.yaml>`_.
        * Support of ServerSide HTTP2 Profile for VS CR, See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/http2>`_.
        * Support HTTP Monitor for Transport Server CR, See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/TransportServer/monitors-transport-server.yaml>`_.
    * Static route support added for ovn-k8s,flannel, cilium and antrea CNI.
    * New parameter --cilium-name to specify BIG-IP tunnel name for Cilium VXLAN integration
    * Support for kubernetes 1.27
    * Support for operator in openshift 4.12
    * Support for AS3 3.47.0

Bug Fixes
````````````
* `Issue 2632 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2632>`_: Fix hubmode support with NodePortLocal
* `Issue 2821 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2821>`_: Fix for additionalVirtualAddresses with serviceAddress config
* `Issue 2550 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2550>`_: Ability to specify monitors for TransportServer CR
* Fix for recreating the LTM objects when CIS restarts in IPAM mode.
* Improved error handling for GTM objects with cccl-gtm-agent.
* Fix crash issue with liveness probe in NextGen routes
* Fix for improper ARPs update in NextGen routes
* Skip processing OSCP system services to enhance performance in NextGen Routes

Upgrade notes
``````````````
* Extended the support of server-side http2 profile which causes existing PolicyCRD to modify accordingly `example <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/Policy/sample-policy.yaml>`_.
* Upgrade the CRDs schema using `CRD Update Guide <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResourceDefinitions/crd_update.md>`_, if you are using custom resources.
* In AS3 >= v3.44 & CIS >= 2.13.0, CIS sets the first SSL profile (sorted in alphabetical order of their names) as default profile for SNI if multiple client SSL certificates used for a VS as kubernetes secrets. AS3 used to set the default SNI in earlier version.


2.12.1
-------------

Added Functionality
```````````````````
* Next generation routes. See `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details.
    * Support for WAF with A/B deployments in routes
* CRD
    * Support for ExternalIP update of associated services of Type LB in TS CR
    * Support for new GTM partition in as3 mode
        * CIS will create a new partition for GTM with partition name {defaultpartition_gtm} in as3 mode

Bug Fixes
````````````
* `Issue 2725 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2725>`_: AS3 label not working with AS3 configmap when filter-tenants set to true.
* `Issue 2793 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2793>`_: TLSProfile crd not working when the SSL profile is from Shared location.
* `Issue 2797 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2797>`_: TLSProfile deletes a referenced SSL Profile when making changes or deleting a VS.
* `Issue 2799 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2799>`_: VirtualServer deletes a referenced iRule when making changes or deleting a VS.
* `Issue 2789 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2789>`_: AS3 Post delay - Not working as expected.
* `Issue 2816 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2816>`_: Fix Error Not found cis.f5.com/ipamLabel
* `Issue 2796 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2796>`_: EDNS not working when deployed before TS
* `Issue 2790 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2790>`_: CIS sends multiple AS3 requests for a single VS

2.12.0
-------------

Added Functionality
```````````````````
**What’s new:**
    * Next generation routes. See `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details.
        * Support for rewrite-app-root annotation in routes
        * Support for WAF annotation in routes
        * Support for allow-source-range annotation in routes
        * Support for targetPort in route's health monitors
    * Ingress
        * Support for partition annotation in Ingress
        * Added wildcard character(*) validation for ingress path
    * CRD
        * Support for ipIntelligencePolicy with policy CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/Policy/sample-policy.yaml>`_
            * Support for configuring ratio on GSLBDomainPool with externaldns CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/ExternalDNS/externaldns-pool-ratio.yaml>`_
        * Support for BIGIP partition with Virtual Server, Transport Server and IngressLink custom resources See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/partition>`_
        * Support for none as value for iRules in policy CR and virtual server CR to disable adding default CIS iRule on BIGIP. See `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource>`_ for more details.
        * Support for path/pool based WAF for VS CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/pool-waf>`_
        * `Issue 2737 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2737>`_: Support for serviceNamespace field in transport server spec that allows to define a pool service from another namespace for transport server CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/TransportServer/serviceNamespace>`_
        * `Issue 2682 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2682>`_: Support to Enable "HTTP MRF Router" on VirtualServer CRD required for HTTP2 Full Proxy feature. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/HttpMrfRoutingEnabled>`_
        * `Issue 2666 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2666>`_: Support for multiple virtual addresses on VirtualServer CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/virtual-with-multiplevip/>`_
        * `Issue 2729 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2729>`_: Support for named port with servicePort. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/virtual-with-named-port>`_
        * `Issue 2744 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2744>`_: Support for Host header rewrite in VirtualServer CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/HostRewrite>`_
    * Helm Chart Enhancements
        * Support for podSecurityContext
        * Support for bigip-login secret creation
        * Support for latest CRD schema
        * Fix for nesting of ingressClass definitions
    * Support for --http-client-metrics deployment parameter to export the AS3 http client prometheus metrics

Bug Fixes
`````````
* `Issue 2703 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2703>`_: Fix host group having multiple hosts with EDNS.
* `Issue 2726 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2726>`_: Fix prometheus metrics broken in v2.11.1
* `Issue 2767 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2767>`_: Fix wrong pool member port configured
* `Issue 2764 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2764>`_: Remove unwanted TLS iRule deployed on reencrypt when passing XFF
* `Issue 2677 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2677>`_: Remove NotReady state nodes from BIGIP poolmembers in NodePortMode
* `Issue 2686 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2686>`_: Validate insecure Virtual Server CR
* LTM policy fix for default http and https ports

Vulnerability Fixes
```````````````````
+------------------+------------------------------------------------------------------+
| CVE              | Comments                                                         |
+==================+==================================================================+
| CVE-2022-40897   | Upgraded the setuptools package in f5-cccl                       |
+------------------+------------------------------------------------------------------+
| CVE-2022-23491   | Upgraded certifi package in f5-cccl repository                   |
+------------------+------------------------------------------------------------------+
| CVE-2022-21698   | Upgraded prometheus vendor package in k8s-bigip-ctlr repository  |
+------------------+------------------------------------------------------------------+
| CVE-2022-27664   | Upgraded golang in k8s-bigip-ctlr repository                     |
+------------------+------------------------------------------------------------------+
| CVE-2021-43565   | Upgraded golang in k8s-bigip-ctlr repository                     |
+------------------+------------------------------------------------------------------+
| CVE-2022-27191   | Upgraded golang in k8s-bigip-ctlr repository                     |
+------------------+------------------------------------------------------------------+

Known Issues
`````````````
* Partition annotation change for ingress intermittently cause AS3 422 error. When error, delete the old ingress & recreate the ingress with new partition.
* Partition change for custom resources (VS/TS/IngressLink) may cause AS3 422 error for default partition. When error, restart the CIS controller.

Upgrade notes
``````````````
* Refer `guide <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/next-gen-routes/migration-guide.md>`_ to migrate to next generation routes.
* Deprecated extensions/v1beta1 ingress API and it's no longer processed by CIS >=2.12. Use the networking.k8s.io/v1 API for ingress.
* Deprecated CommonName support for host certificate verification in secrets,  use subject alternative name(SAN) in certificates instead.

FIC 0.1.9 Release notes :
-------------------------

Added Functionality
```````````````````
**What’s new:**
    * Base image upgraded to RedHat UBI-9 for FIC Container image

Bug Fixes
````````````
* `Issue 2747 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2747>`_ Fix to persist IP addresses after CIS restart


2.11.1
------

Added Functionality
```````````````````
* Next generation routes preview. See `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details.
    * Support for default routeGroup (Migration Only)
* Base image upgraded to RedHat UBI-9 for CIS Container image
* Support for AS3 3.41.0

Bug Fixes
`````````
* Added pattern definition in CR schema to align with F5 BIG-IP Object Naming convention
* `Issue 2153 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2153>`_: Updated go.mod to v2
* `Issue 2657 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2657>`_: WAF policy name does not allow hyphen (-)

Documentation
`````````````
* Updated user guides (`See here <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/user_guides/README.md>`_)
* `Issue 2606 <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2606>`_: Applying setup files from Clouddocs fails.

CIS Helm Chart Fixes
````````````````````
* CRD Schema Update
* RBAC Update

FIC Helm Chart Fixes
````````````````````
* Added support for Infoblox credentials using k8s secrets in helm charts


2.11.0
-------------

Added Functionality
```````````````````
**What’s new:**
    * Next generation routes preview. Refer `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details.
        * Policy CR integration with extended ConfigMap
        * EDNS CR integration with extended ConfigMap
        * Support for Default SSL profiles from baseRouteSpec in extended Configmap
        * Support Path based A/B deployment for Re-encrypt termination
        * Support for TLS profiles as K8S secrets in route annotations. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/routes>`_
        * Support for TLS profiles as route annotations. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/routes>`_
        * Support for health monitors using route annotations See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/routes>`_
        * Support to create Health Monitor from the pod liveness probe for routes. Refer `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details
    * CRD
        * CIS configures GTM configuration in default partition
        * Pool reselect support for VS and TS. `Example for VS <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/pool-reselect/vs-with-pool-reselect.yaml>`_ ,
          `Example for TS <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/TransportServer/tcp-transport-server.yaml>`_
        * Support for allowVlans with policy CR.
        * Support for --cccl-gtm-agent deployment parameter to set the gtm agent
        * Support to provide the same VIP for TS and VS CRs using hostGroup. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/virtual-with-hostGroup>`_
        * :issues:`2420` Support for nodeMemberLabel in Transport Server pool. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/TransportServer/>`_
        * :issues:`2469` Support for virtual server grouping by hostgroup across namespaces.From 2.11, hostGroup should be unique across namespaces.See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/virtual-with-hostGroup>`_
        * :issues:`2585` Support for multiple clientssl & serverssl profiles in TLS Profiles. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/virtual-with-hostGroup>`_
        * :issues:`2637` Support for custom persistence profile. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/persistenceProfile>`_

    * Ingress
        * Support for Translate Address annotation in ingress.
        * Support for sslProfile in HTTPS health monitors for ingress. `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/ingress/networkingV1/>`_

Bug Fixes
````````````
* :issues:`2581` IPAM to provide the same IP for different TS
* :issues:`2586` Update ExternalIP of associated services of Type LB for VS and IngressLink CR
* :issues:`2609` TargetPort support for string with NPL
* :issues:`2626` Process IngressLink on K8S node update
* Fix to remove old ingress monitor when type gets modified
* Fix to send AS3 declaration for the recreated domain after IPAM controller restart

FIC Helm Chart Fixes
``````````````````````
* :issues:`130` IPAM Helm Deployment strategy should be recreate


2.10.1
-------------
Bug Fixes
````````````
* Fix to monitor NGINX+ service changes
* :issues:`2582` Fix issue with inconsistent pool names for VS
* :issues:`2596` Fix invalid property name with serviceAddress
* :issues:`2570` Fix for TLSProfile doesn't get updated when K8s secret changes
* :issues:`2394` Fix to set ingress https monitor send string
* :issues:`2549` Fix trafficGroup regex
* :issues:`2492` Fix for shared pool not working in nodePort mode


2.10.0
-------------

Added Functionality
```````````````````

**What’s new:**
    * Next generation routes preview. Refer `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details
        * Added new base config block for TLSCiphers in extended ConfigMap. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/configmap>`_
        * Support for namespaceLabel in extended ConfigMap. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/configmap>`_
        * Support for BigIP ClientSSL/ServerSSL profile reference in extended ConfigMap. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/configmap>`_
        * Support for allowSourceRange in extended ConfigMap. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/configmap>`_
        * rewrite-target-url support via route annotations. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/routes>`_
        * Load Balancing support via route annotation. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes/routes>`_
        * Support for AB Deployment in routes
    * CRD:
        * allowSourceRange support for VirtualServer CRs and Policy CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * Added support for TCP Health Monitor support in VS CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/HealthMonitor>`_
        * Added support for multiple monitors in VS and TS CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * SCTP support for Transport Server Custom Resource. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/TransportServer>`_
        * :issues:`2201` Support for linking existing health monitor on bigip with virtualSever and TransportServer CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * :issues:`2361` Allow monitoring of an alias port in VirtualServer and TransportServer. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * :issues:`1933` Added serviceNamespace field in Pools for VirtualServer CR that allows to define a pool service from another namespace in a Virtual server CR.
          See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_

    * Ingress:
        * Added support to configure netmask for Virtual Server for Ingress. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/ingress/>`_
    * Support for Cilium CNI (>=v1.12.0) in kubernetes cluster. See `Examples <https://github.com/f5devcentral/f5-ci-docs/blob/master/docs/cilium/cilium-bigip-info.rst>`_
    * Support for --log-file deployment parameter to store the CIS logs in a file
    * Support for AS3 3.38.0
    * Support for operator in openshift 4.10 & openshift 4.11


Bug Fixes
````````````
* Fix CIS continuous processing of ingress belonging to unmanaged ingress class
* :issues:`2325` Supporting Prometheus service in CRDs
* :issues:`2158` CIS send logs to file from container
* :issues:`2345` CIS crash due to Route Profiles
* :issues:`2507` Monitor name by accident includes health check command
* :issues:`2413` Hyphens/dashes not allowed in VirtualServer pool path


2.9.1
-------------

CIS Compatibility
```````````````````
**CIS is now compatible with:**
    * Kubernetes 1.23
    * OCP 4.10 with OVN & SDN CNI

Bug Fixes
````````````
* :issues:`2336` Fix confusing EDNS Pool name
* :issues:`2337` Fix for EDNS pool deletion with invalid server config
* :issues:`2484` Fix scalability issue of LB services with IPAM processing
* :issues:`2464` Fix pool members empty issue with HubMode
* :issues:`2308` Fix ARP deletion in filter-tenant mode
* Fix Invalid traffic Allow in Ingress with Custom HTTP Port

CIS Helm Chart Fixes
``````````````````````
* :issues:`2422` Fix securityContext wrong indentation
* :issues:`2434` Helm install values.yaml results in a bad image format
* Updated links in helm values.yaml documentation

FIC Helm Chart Fixes
``````````````````````
* :issues:`104` Fix modifying invalid ipamLabel for a typeLB service
* :issues:`96` Added PVC creation to Helm charts
* :issues:`102` Added tolerations support with Helm charts
* Added support for multiple infoblox labels with Helm charts


2.9.0
-------------
Added Functionality
```````````````````

**What’s new:**
    * Next generation routes preview. Refer `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/next-gen-routes>`_ for more details
        * Multiple VIP and partition support for routes
    * CRD:
        * LoadBalancingMethod support for VirtualServer and TransportServer CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * DoS Protection Profile support for VirtualServer, TransportServer and Policy CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * Bot Defense Profile support for VirtualServer and Policy CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * Protocol profile(client) support for TransportServer and Policy CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * OneConnect profile support added for VirtualServer CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * Custom TCP Client and Server profile support added for VirtualServer, TransportServer and Policy CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * SNAT pool name support in Policy CR for VirtualServer, TransportServer CRs. See `Example <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResource/Policy/sample-policy.yaml>`_
        * Custom pool name support in VirtualServer and TransportServer CRs. See `Example <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/customPoolName>`_
        * GTM global-availability LB method and order precedence support with EDNS CRs. See `Examples <https://github.com/sravyap135/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/ExternalDNS>`_
    * Service Type LoadBalancer:
        * SCTP protocol support in Services of type LoadBalancer. See `official documentation <https://kubernetes.io/docs/reference/networking/service-protocols/#protocol-sctp>`_
        * Added support for attaching Policy CRD as an annotation
            * SNAT pool name support in policy CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
    * ConfigMap:
        * :issues:`2326` Support for Configmap resource with NodePortLocal mode
    * Routes :
        * Added support for route admit status for rejected legacy and next gen routes

    * Added support for AS3 3.36, OCP 4.9
* Helm Chart Enhancements:
    * Support for latest CRD schema
    * issues:`2387` Inconsistent use of value in f5-bigip-ctlr helm chart

Bug Fixes
````````````
* :issues:`2224` Selecting Load Balancing method on VS CRD
* :issues:`2323` Fixed file and examples links in ingresslink document
* :issues:`2151` Fix for adding unique pool members only to AS3 declaration with AS3 configmap
* SR : Added fix for CIS crash with routes
* Fix for different service Port and target port with CRs

Upgrade notes
``````````````
* Some of the new features require an update to Custom resource definition file.

FIC 0.1.8 Release notes :
-------------------------
Added Functionality
```````````````````
* Support for label with multiple IP ranges with comma seperated values :issues:`101`. See `documentation <https://raw.githubusercontent.com/F5Networks/f5-ipam-controller/main/docs/config_examples/f5-ip-provider/ipv4-addr-range-default-provider-deployment.yaml>`_

Bug Fixes
````````````
* :issues:`115` Reference handled properly in Database table

Known Issues
`````````````
* Appending new pool to existing range using the comma operator triggers FIC to reassign the newIP with new IP pool for the corresponding ipamLabel domains/keys


2.8.1
-------------
Bug Fixes
````````````
* :issues: 2030  Changes to Ingress resource ServicePort are now reflected on BIG-IP.
* :issues: 2205  Bulk deletion of EDNS handled properly.
* :issues: 2255  ServicePort is now optional and multi-port service handled properly in ConfigMaps.
* :issues: 2164  CIS properly updates configuration in BIGIP when configured with agent CCCL and log-level DEBUG.
* :issues: 2191  CIS properly logs iApps when configured with agent CCCL.
* :issues: 2220  CRD VirtualServer status reported correctly when using hostGroup.
* :issues: 2209  ConfigMap errors logs now contain ConfigMap name and namespace.
* SR - CIS configured in CCCL agent mode properly updates BIG-IP when there are no backend pods to iApps ConfigMaps

FIC Bug Fixes
````````````````
* :issues: 98  IPAM Storage initialisation handled properly.

2.8.0
-------------
Added Functionality
```````````````````

**What’s new:**
    * CRD:
        * Persistence Profile support for VirtualServer, TransportServer and Policy CRs. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * Added support for host in TransportServer and IngressLink CR. See `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/>`_
        * Added support for multiple health monitors in EDNS resource, Refer `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/ExternalDNS>`_
    * NodePortLocal(NPL) Antrea CNI feature support added to Ingress and Virtual Server Custom Resource, Refer `Documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/NodePortLocal>`_
    * Helm Chart Enhancements:
        * Support for latest CRD schema

Bug Fixes
````````````
* Added fix for processing oldest route when same host and path in routes
* Added fix for cis crash with routes
* :issues: 2212  Fix ExternalDNS adds both VSs to a Wide IP pool with using "httpTraffic: allow" with VS CR
* :issues: 2221  Fixed Error in CIS logs while deleting multiple VS CRD
* :issues: 2222  Fix deleting VirtualServer using hostGroup
* :issues: 2233  TS and VS CRD don't detect the pool members for grafana service
* :issues: 2234  Fix for CIS crash with subsequent creation and deletion of wrong ConfigMap
* :issues: 2077  CIS deletes all existing ARP on restart and recreates it, which affects traffic

2.7.1
-------------
Bug Fixes
````````````
* Optimized processing of ConfigMaps with FilterTenants enabled
* Added support for multihost VS policy rules for same path and service backend combination
* Improved error handling with EDNS Custom resource
* :issues: 1872 Support protocol UDP in Services of type LoadBalancer
* :issues: 1918 ExternalDNS adds both VSs to a Wide IP pool
* :issues: 2051 Fix AS3 Postdelay issue when error occurs
* :issues: 2077 Fix recreating ARPs when CIS restarts
* :issues: 2172 Fix Endpoint NodeName validation issue
* Helm Chart Enhancements:
    - issues: 2184 Helm Chart ClusterRole does not have correct permissions

FIC Enhancements
````````````````
* Added support for FIC installation using Helm Charts, Refer `Documentation <https://github.com/F5Networks/f5-ipam-controller/blob/main/helm-charts/f5-ipam-controller/README.md>`_
* Added support for FIC installation using OpenShift Operator

Known issues
````````````
* CIS does not delete the arp entries immediately from BigIP, When we remove all the endpoints for a service in cccl mode,
* Unable to pass multiple infoblox labels to FIC helm charts & OpenShit Operator
* Deletion of EDNS resource not removing Wide IP config from BigIP intermittently
* CIS sends the failed tenant declaration every 30 secs with filter-tenant parameter when a 422 error occurs in as3 response

Upgrade notes
``````````````
* Moving from CIS > 2.6 with IPAM, see troubleshooting guide for IPAM issue ``ipams.fic.f5.com not found``. Refer `Troubleshooting Section <https://github.com/F5Networks/f5-ipam-controller/blob/main/docs/faq/README.md>`_
* Moving to CIS > 2.4.1 requires update to RBAC and CR schema definition before upgrade. See `RBAC <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/rbac/clusterrole.yaml>`_ and `CR schema <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml>`_


2.7.0
-------------
Added Functionality
```````````````````

**What’s new:**
    * CRD:
        * Policy CR support for VirtualServer and TransportServer CR. `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/Policy>`_
        * Support for L3 WAF, L7 Firewall policy and various profiles.
        * IPv6 address support for VirtualServer, TransportServer CR and ServiceTypeLB service. `Examples <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResource/VirtualServer/virtual-server-name-address/custom-ipv6-virtual-server-address.yaml>`_
        * Wildcard domain name support with TLSProfile and VirtualServer. `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/virtual-with-wildcard-domain>`_
        * Multi-host support in VirtualServer CR using hostgroup parameter. `Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/VirtualServer/virtual-with-hostGroup>`_
        * New Status column for VirtualServer and TransportServer CR. `GitHub issue <https://github.com/F5Networks/k8s-bigip-ctlr/issues/1659>`_
        * EDNS:
            * TCP type monitor support for EDNS
            * Renamed EDNS resource name from externaldnss to externaldns. `CRD definition <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml>`_
    * ConfigMap:
        * Tenant based AS3 declarations support for configmaps using ``--filter-tenants`` deployment option.
    * Ingress:
        * Named service port reference for ingresses. `GitHub issue <https://github.com/F5Networks/k8s-bigip-ctlr/issues/2031>`_
    * Helm Charts:
        * Support for latest CRD schema

**CIS is now compatible with:**
    * Kubernetes 1.22
    * OCP 4.9 with OVN
    * AS3 3.30

Bug Fixes
````````````
* :issues:1684 [EDNS] CIS tries to remove non-existing monitor from GTM pool
* :issues:1873 Enable /metrics endpoint with crd mode
* :issues:1916 Display IPAM provided IPaddress for TransportServer
* :issues:2014 Allow type LoadBalancer with different TargetPort and Port values
* :issues:2016,2102 Fix for crash while validating secrets
* :issues:2025 Support 'sni-server-name' for GTM HTTPS Monitor
* :issues:2087 Enable nodeMemberLabel regex to support common node labels
* :issues:2053 Remove ECDSA cert SNI support for OpenShift Routes - Revert :issue:1723
* Restructured docs examples directory
* Improved performance while processing VS, services and endpoint resources

Note
````
* Renamed EDNS resource name from externaldnss to externaldns. Refer to latest EDNS CRD definition `here <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml>`_. This latest EDNS schema is compatible only with CIS version >=2.7.0
* Validated IPv6 with calico CNI on k8s 1.22 setup
* Log4j vulnerability does not impact CIS and FIC code base ☺️

Known issues
````````````
* Policy CRD integration with TS CRD has few issues.
* Wildcard hostname in VS CRD doesn’t match the parent domain
* When root domain and wildcard domain refer to same VSAddress, CIS is not working as expected

FIC 0.1.6 Release notes :
-------------------------
Added Functionality
```````````````````
* IPv6 address range configuration support with default f5-ip-provider. `Example <https://raw.githubusercontent.com/F5Networks/f5-ipam-controller/main/docs/config_examples/f5-ip-provider/ipv6-addr-range-default-provider-deployment.yaml>`_


2.6.1
-------------
Bug Fixes
`````````
* Added the complete path for datagroups in http redirect irule
* Added RouteDomain support for AS3 resources
* :issues: 2032 EDNS will not work if both Virtual Server CRD and EDNS CRD applied at the same time
* :issues: 2012 Invalid Pool Name passed to AS3
* :issues: 1931 Cannot disable IngressClass in HelmChart
* :issues: 1911 CIS delete all exist vs when cis pod restarting
* :issues: 1792 EDNS fails to link WIP to Pool, error says "last-resort-pool" needs value in bipctrl log

2.6.0
-------------
Added Functionality
```````````````````
* CIS now compatible with OpenShift 4.8.12
  - Validated with OpenShift SDN and OVN-Kubernetes with hybridOverlay.
* CIS supports IP address assignment to IngressLink Custom Resources using F5 IPAM Controller(See `documentation <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/IngressLink/ingressLink-with-ipamLabel>`_)
* CIS validates IPV6 address in bigip-url & gtm-bigip-url parameter

Bug Fixes
`````````
* :issues: 1679 CIS requires GTM parameter in CIS declaration even if GTM runs on the same BIG-IP
* :issues:1888 Unable to upgrade from 2.2.0 (or below) to 2.2.1 (or above)
* :issues: 1941 CIS 2.5 output DEBUG log even with --log-level=INFO configured
* Fixes issue with deletion of monitor with EDNS custom resource deletion


Performance Improvements
````````````````````````
* Improved EDNS Performance
  New VirtualServer creation triggers processing of only associated EDNS resources.
* Improved ingress Performance

Known Issues
````````````
* EDNS with https monitor is not properly supported.


F5 IPAM Controller v0.1.5
`````````````````````````
Added Functionality
```````````````````
* F5 IPAM Controller supports InfoBlox (See `FIC release notes <https://github.com/F5Networks/f5-ipam-controller/blob/main/docs/RELEASE-NOTES.rst>`_)


2.5.1
-------------

Bug Fixes
`````````
* :issues: 1921 Plain text login and password in process status on node that is running controller.
* :issues: 1849 Fix VirtualServer CRD processing which share same IP and different port.
* CIS now supports:
    * Deletion of old F5IPAM CR which is not in use.
    * Skipping certificate validation for passthrough routes.
    * Update/delete of Ingress V1 annotation with shared IP.
* OpenShift operator doesn't fail to install multiple CIS instances due to already existing CRD's.


Vulnerability Fixes
```````````````````
+------------------+------------------------------------------------------------------+
| CVE              | Comments                                                         |
+==================+==================================================================+
| CVE-2019-19794   | Upgraded the miekg Go DNS package in CIS repository              |
+------------------+------------------------------------------------------------------+

2.5.0
-------------

Added Functionality
```````````````````
* CIS now compatible with:
    - Kubernetes 1.21
    - OpenShift 4.7.13 with OpenShift SDN
    - AS3 3.28

* Added support for:
    - Multiport Service and Health Monitor for Service type LoadBalancer in CRD mode. Refer for `examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/serviceTypeLB>`_.
    - :issues: 1824 Support for Kubernetes networking.k8s.io/v1 Ingress and IngressClass. Refer for `examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/ingress/networkingV1>`_.
    - For networking.k8s.io/v1 Ingress, add multiple BIGIP SSL client profiles with annotation ``virtual-server.f5.com/clientssl``. Refer for `examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/ingress/networkingV1>`_.
    - OpenShift route annotations ``virtual-server.f5.com/rewrite-app-root`` (`examples <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/routes/sample-route-rewrite-app-root.yaml>`_) and ``virtual-server.f5.com/rewrite-target-url`` (`examples <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/routes/sample-route-rewrite-target-url.yaml>`_) with agent AS3.
    - :issues: 1570 iRule reference in TransportServer CRD.  Refer for `examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/TransportServer>`_.
    - CIS deployment configuration options:
         * ``--periodic-sync-interval`` - Configure the periodic sync of Kubernetes resources.
         * ``--hubmode`` - Enable Support for ConfigMaps to monitor services in same and different namespaces.
         * ``--disable-teems`` - Configure to send anonymous analytics data to F5.
* CIS now monitors changes to Kubernetes Secret resource.
* Improved performance while processing Ingress resources.
* CIS in AS3 agent mode now adds default cipher groups to SSL profiles for TLS v1.3.
* CIS now supports `F5 IPAM Controller 0.1.4 <https://github.com/F5Networks/f5-ipam-controller/blob/main/docs/RELEASE-NOTES.rst>`_.

* Helm Chart Enhancements includes:
    - Latest CRD schemas
    - IngressClass installation

Bugs Fixes
``````````
* CIS now properly adds nodes as pool members (in NodePort mode).


Known Issues
````````````
* For improved performance, configure CIS deployment with ``--periodic-sync-interval`` more than 300 seconds. OpenShift Routes with termination Passthrough get processed post this interval.

Before upgrade to 2.5
`````````````````````
* CIS 2.5 supports Kubenetes networking.k8s.io/v1 Ingress and IngressClass. With Kubernetes > 1.18, 
    - Reconfigure CIS `ClusterRole <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/rbac/clusterrole.yaml>`_ - we removed `resourceName` to monitor all secrets.
    - Create `IngressClass <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/ingress/networkingV1/example-default-ingress-class.yaml>`_ before version upgrade.
* To upgrade CIS using operator in OpenShift, 
    - Install `IngressClass <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/ingress/networkingV1/example-default-ingress-class.yaml>`_ manually. 
    - Install `CRDs <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml>`_ manually if using CIS CustomResources (VirtualServer/TransportServer/IngressLink).


F5 IPAM Controller v0.1.4
``````````````````````````

Added Functionality
```````````````````
* F5 IPAM Controller supports InfoBlox (Preview - Available for VirtualServer CR only. See `documentation <https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md>`_).


2.4.1
-------------
Added Functionality
```````````````````
* CIS supports `F5 IPAM Controller 0.1.3 <https://github.com/F5Networks/f5-ipam-controller/blob/main/docs/RELEASE-NOTES.rst>`_.
* Helm Chart Enhancements:
    - Added support for multiple namespace configuration parameter with CIS operator.

Bug Fixes
`````````
* :issues: 1737 Inconsistent ordering of policy rules when adding an Ingress path.
* :issues: 1808 K8S BIG-IP Controller upload old certificate to BIG-IP.
* Stale IPAM CR configuration gets deleted on CIS restart.
* IPAM allocated IP address now populates for VirtualServer under VSAddress column.
* CIS supports endpoints created without nodeNames in Cluster mode for Headless Service.
* Updated helm charts to support IBM platform certification.

Vulnerability Fixes
```````````````````
+------------------+------------------------------------------------------------------+
| CVE              | Comments                                                         |
+==================+==================================================================+
| CVE-2020-36242   | Upgraded cryptography package in f5-common-python repository     |
+------------------+------------------------------------------------------------------+
| CVE-2020-25659   | Upgraded cryptography package in f5-cccl repository              |
+------------------+------------------------------------------------------------------+
| CVE-2020-14343   | Upgraded PyYAML package in f5-cccl repository                    |
+------------------+------------------------------------------------------------------+

Limitations
```````````
Due to changes in the BIG-IP Python API, CIS EDNS no longer functions correctly. EDNS will be moving to the AS3 API in the upcoming release


2.4.0
-------------
Added Functionality
```````````````````
* CIS is now compatible with:
    -  Kubernetes 1.20
* CIS supports IP address assignment to kubernetes service type LoadBalancer using `F5 IPAM Controller <https://github.com/F5Networks/f5-ipam-controller/releases>`__. Refer for `Examples <https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md>`_.
* CIS supports IP address assignment to TransportServer Custom Resources using `F5 IPAM Controller <https://github.com/F5Networks/f5-ipam-controller/releases>`__. Refer for `Examples <https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md>`_.
* Added support for defaultRouteDomain in custom resource mode.
* CIS supports service address reference in VirtualServer and TransportServer Custom Resources.
* Integrated the IngressLink mode with CRD mode.
* CIS supports implicit Health Monitor for IngressLink resource.
* Improved data group handling for VirtualServer custom resource.
* Helm Chart Enhancements:
    - Updated the Custom Resource Definitions for VirtualServer and TransportServer resources.
    - Added the IngressLink Custom Resource installation using Helm charts.
    - Updated the RBAC to support service type LoadBalancer.

Bug Fixes
`````````
* SR - Fix continuous overwrites with iApp in cccl mode.
* :issues: 1573 Added support for type UDP Transport Server CRD.
* :issues: 1723 BIG-IP selects wrong certificate with ECDSA-signed certificate.
* :issues: 1645 Certificate-check added in CISv2.2.2 logs too often.
* :issues: 1730 Partition default_route_domain is being reset while creating VirtualServer via CRD to 0.
* :issues: 1767 HTTPs redirect Data Group entry not cleaned up.

Vulnerability Fixes
```````````````````
+------------------+----------------------------------------------------------------+
| CVE              | Comments                                                       |
+==================+================================================================+
| CVE-2020-1747    | Upgraded the PyYaml package in f5-cccl repository              |
+------------------+----------------------------------------------------------------+
| CVE-2020-25659   | Removed unused package cryptography in f5-cccl repository      |
+------------------+----------------------------------------------------------------+

Limitations
```````````
* :issues: 1508 VXLAN tunnel name starting with prefix "k8s" is not supported. CIS uses prefix "k8s" to differentiate managed and user created resources.


2.3.0
-------------
Added Functionality
```````````````````
* CIS supports IP address assignment to Virtual Server CRD using `F5 IPAM Controller <https://github.com/F5Networks/f5-ipam-controller/releases>`__. Refer for `Examples <https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md>`_.
* CIS allows user to leverage Virtual IP address using either `F5 IPAM Controller <https://github.com/F5Networks/f5-ipam-controller/releases>`__ or virtualServerAddress field in VirtualServer CRD
* Support Passthrough termination for TLS CRD
* Added support for AS3 schema minor versions
* :issues: 1631 Support `caCertificate` for OpenShift Routes
* :issues: 1571 iRule reference for VirtualServer CRDs
* :issues: 1592 :issues:`1621` Enabling VLANS for VirtualServer and TransportServer CRDs
* Updated CR Kind from `NginxCisConnector` to `IngressLink`
* Helm Chart Enhancements:
    - Added Support for `livenessProbe <https://github.com/F5Networks/charts/issues/34>`_, `ReadinessProbe <https://github.com/F5Networks/charts/issues/34>`_, `nodeSelectors <https://github.com/F5Networks/charts/issues/38>`_, `tolerations <https://github.com/F5Networks/charts/issues/38>`_.
    - :issues: 1632  Added Support for skipping CRDs.

Bug Fixes
`````````
* :issues: 1457 Each Client request get logged on BIG-IP when http2-profile associated to VS
* :issues: 1458 CISv2.1.0 does not delete LTM-Policy reset-rule when removed the whitelist-source-range OpenShift annotation
* :issues: 1498 openshift_passthrough_irule could not set the variable "$dflt_pool" correctly when http/2-profile linked to VS
* :issues: 1565 Logs should distinguish configmap and Ingress errors
* :issues: 1641 Debug log sKey.ServiceName in syncVirtualServer
* :issues: 1671 TransportServer assigns wrong pool/service
* SR: CIS fail to update pod arp on BigIP,"Attempted to mutate read-only attribute(s)"
* CIS allowing to access all non-belonging pool members from a single reachable VIP in CRD mode.

Limitations
```````````
* For AB routes HTTP2 traffic does not distribute properly when http2-profile associated to VS
* Workaround for CIS in `IPAM mode <https://github.com/F5Networks/f5-ipam-controller/blob/main/README.md>`_.
* Removing virtualServerAddress field from VSCRD in non-IPAM mode may flush corresponding BIGIP configuration


2.2.3
-------------
Bug Fix
`````````
* :issues: 1646 Virtual Server demoted from CMP when updating to CISv2.2.2


2.2.2
-------------
Added Functionality
```````````````````
* CIS is now compatible with:
    -  OpenShift 4.6.4.
    -  Kubernetes 1.19
    -  BIGIP v16
    -  AS3 3.25.
* CIS handles validation of BIG-IP ClientSSL/ServerSSL.
* Support for error handling in CRDs.

Bug Fixes
`````````
* :issues: 1557 iRule openshift_passthrough_irule logs various TCL errors.
* :issues: 1584 iRule openshift_passthrough_irule logs TCL errors - can't read "tls_extensions_len”.
* :issues: 1602 ConfigMap not working for 2.2.1 but works for 2.2.0.
* SR - CIS now properly handles incorrect configMap with syntax errors.
* CIS now log messages when processing multiple EDNS.
* CIS now handles the duplicate and invalid routes properly.
* CIS now updates global parameters SNAT by every Virtual server pointing to the same hostname.
* CIs handles duplicate path issue with virtual server pointing to same host or virtual address.
* CIS handles MAC address parsing issue with new flannel versions.
* CIS now processes configMap updates properly.


2.2.1
-------------
Added Functionality
```````````````````
* CIS is now compatible with:
    -  OpenShift 4.6.4.
    -  AS3 3.24.
* CIS supports OVN-Kubernetes CNI for Standalone and HA with OSCP 4.5.
* External DNS CRD – Preview available in CRD mode.
    -  Supports single CIS to configure both LTM and GTM configuration.
    -  Supports external DNS for GTM configuration.
    -  Create wide-IP on BigIP using Virtual server CRD's domain name
    -  Multi cluster support for same domain
    -  Health montior support for monitoring GSLB pools
    -  CIS deployment parameter added `--gtm-bigip-url`, `--gtm-bigip-username`, `--gtm-bigip-password` and `--gtm-credentials-directory` for External DNS.
    -  `CRD schema definition for External DNS <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml>`_.
    -  `CRD examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource/ExternalDNS>`_.

Bug Fixes
`````````
* :issues: 1464 CIS AS3 does not support k8s services has multiple port.
* :issues: 1391 Expose Kubernetes api services via F5 ingress crashes CIS.
* :issues: 1527 Service Discovery logs not being output.
* SR - Fix for concurrent map read and write with configmap processing.
* SR - Improved performance by skipping the processing of endpoints for unassociated services

Limitations
```````````
* On updating or deleting CIS virtual server CRD's virtualServerAddress for a domain, CIS does not update the GSLB pool members.
* CIS is unable to delete the Wide-IP without Health Monitor.
* CIS is unable to delete the Health Monitor when there are no virtual server CRD available for a domain name.

2.2.0
-------------
Added Functionality
`````````````````````
**Custom Resource Definition (CRD)**

* Multiple ports in a single service.
* `TrasnsportServer` Custom Resource.
* VirtualServer Custom Resource without Host Parameter.
* Share Nodes implementation for CRD, Ingress and Routes.
* WAF Integration.
* SNAT in VirtualServer CRD.
* Option to configure Virtual address port.
* App-Root Rewrite and Path Rewrite.
* Health Monitor for each pool member.
* Option to configure VirtualServer name.
* Nginx CIS connector.
* Namespace label.
* CRD TEEMs Integration.
* Support for AS3 3.23.
* Upgraded AS3 Schema validation version from v3.11.0-3 to v3.18.0-4.
* `CRD Schema <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml>`_.
* `CRD Examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource>`_.

Bug Fixes
`````````
**Custom Resource Definition (CRD)**

* Verify the AS3 installation on BIGIP in CRD Mode.
* Streamlined logs.
* Fix unnecessary creation of HTTP VirtulServer when httpTraffic is None.

**Routes**

* Fix FlipFlop of Policy with AB deployment Routes.
* Remove unwanted logs from IRule.

Limitations
```````````
* Modifying VirtualServer address leads to traffic loss intermittently. Delete and re-create the VirtualServer as an alternative.
* VirtualServers with same host and virtualServerAddress should maintain same parameters except pool, tlsProfileName and monitors.

2.1.1
-------------
Added Functionality
`````````````````````
* CIS is now compatible with:
       -   OpenShift 4.5.
       -   AS3 3.21.
* Custom Resource Definition (CRD) – Preview version available with `virtual-server` and `TLSProfile` custom resources.
      - `CRD Doc and Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/CustomResource.md>`_.
* Custom Resource Definition (CRD) – Added Support for k8s Secrets with TLSProfile Custom Resource.
* Custom Resource Definition (CRD) – Improved the strategy of processing `virtual-server` and `TLSProfile` custom resources.
* Custom Resource Definition (CRD) – Added support for installation using Helm and Operator.
* Custom Resource Definition (CRD) – Streamlined logs to provide insightful information in INFO and remove unwanted information in DEBUG mode.

Bug Fixes
`````````
* :issues: 1467 AS3 ERROR declaration.schemaVersion must be one of the following with Controller version 2.1.0.
* :issues: 1433 Template is not valid. When using CIS 2.1 with AS3 version: 3.21.0.
* :issues: 1440 Optional health check parameters don't appear to be optional.
* Fixed issues with processing multiple services with same annotations in AS3 ConfigMap mode.
        - When there are multiple services with same annotations, CIS updates the oldest service endpoints in BIG-IP.
* Fixed issues with continuous AS3 declarations in CRD mode.
* Fixed issues with re-encrypt termination on multiple domains in CRD mode.
* Fixed issues with crashing of CIS in CRD mode.
        - When user removes f5cr label from `VirtualServer` or `TLSProfile` custom resources.
        - When user deletes `TLSProfile` custom resource. This behaviour is intermittent.
* Fixed issues with processing of unwanted endpoint and service changes in CRD mode.

Limitations
```````````
* During restarts, CIS fails to read `TLSProfile` custom resource. This behaviour is intermittent.
* CIS does not update the endpoint changes on BIG-IP in CRD mode. This behaviour is intermittent.
* CIS does not validate secrets and BIG-IP profiles provided in `TLSProfile` custom resource.
* CIS supports only port 80 and 443 for BIG-IP Virtual servers in CRD mode.

2.1
-------------
Added Functionality
```````````````````
* CIS will not create `_AS3` partition anymore.
    -  CIS uses single partition(i.e. `--bigip-partition`) to configure both LTM and NET configuration.
    -  Removes Additional AS3 managed partition _AS3, if exists.
* Enhanced performance for lower BIG-IP CPU Utilization with optimized CCCL calls.
* CIS 2.x releases requires AS3 versions >= 3.18.
* CIS is now compatible with:
   -  OpenShift 4.4.5.
   -  AS3 3.20.
* Added support for:
   -  Multiple AS3 ConfigMaps.
   -  AS3 label switching in AS3 ConfigMap resource
          *  when set to False, CIS deletes the existing Configuration (or) CIS ignores AS3 ConfigMap.
          *  When set to True, CIS reads the corresponding AS3 ConfigMap.
   -  Added Whitelist feature support for agent AS3 using policy endpoint condition
          *  New annotation "allow-source-range" added parallel to "whitelist-source-range".
* Deprecated `--userdefined-as3-declaration` CIS deployment option as CIS now supports Multiple AS3 ConfigMaps
* Custom Resource Definition (CRD) – Preview available with TLS support.
    - Few Highlights of this Preview CRD version:
             *  Supports single partition to configure both LTM and NET configuration.
             *  Supports both unsecured and TLS CRD.
             *  Supports single domain per Virtual server
             *  Supports merging multiple virtual servers into single BIG-IP VIP referring to single domain
             *  Added Health montior support
             *  Supports nodelabel in Virtual server CRD
             *  Supports TLSProfile CRD with BIG-IP reference client and server SSL profiles
             *  Supports TLSProfile CRD with K8S secrets reference for client SSL profiles.
             *  `CRD schema definition for both Virtual server and TLSProfile <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/master/docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml>`_.
             *  `CRD examples <https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/customResource>`_.

Bug Fixes
`````````
* :issues: 1420 Enhanced performance for lower BIG-IP CPU Utilization with optimized CCCL calls.
* :issues: 1362 CIS supports HTTP Header with iv-groups
* :issues: 1388,1311 CIS properly manages AS3 ConfigMaps when configured with namespace-labels.
* :issues: 1337 CIS supports multiple AS3 ConfigMaps
* :issues: 1171 CIS will not create `_AS3` partition anymore

Vulnerability Fixes
```````````````````
+------------------+------------------------------------------------------------------------------------+
| CVE              | Comments                                                                           |
+==================+====================================================================================+
| CVE-2018-5543    | CIS Operator uses --credentials-directory by default for BIG-IP credentials        |
+------------------+------------------------------------------------------------------------------------+

Archived CF and Mesos Github repos
``````````````````````````````````
* This projects are no longer actively maintained
     -     `cf-bigip-ctlr <https://github.com/F5Networks/cf-bigip-ctlr>`_
     -     `marathon-bigip-ctlr <https://github.com/F5Networks/marathon-bigip-ctlr>`_

Guidelines for upgrading to CIS 2.1
```````````````````````````````````
* Those migrating from agent CCCL to agent AS3 :
     - User should clean up LTM resources in BIG-IP partition created by CCCL before migrating to CIS 2.1.
          Steps to clean up LTM resources in BIG-IP partition using AS3
           *  Use below POST call along with this `AS3 declaration <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/v2.6.1/docs/config_examples/example-empty-AS3-declaration.yaml>`_.
                - mgmt/shared/appsvcs/declare
           *  Note: Please modify <bigip-ip> in above POST call and <bigip-partition> name in `AS3 declaration <https://raw.githubusercontent.com/F5Networks/k8s-bigip-ctlr/v2.6.1/docs/config_examples/example-empty-AS3-declaration.yaml>`_

2.0
-------------
Added Functionality
`````````````````````
* `as3` is the default agent. Use deployment argument `--agent` to configure `cccl` agent.
* Custom Resource Definition (CRD) – Alpha available with Custom resource `virtual-server`.
      - `CRD Doc and Examples <https://github.com/F5Networks/k8s-bigip-ctlr/blob/master/docs/config_examples/customResource/CustomResource.md>`_.
* Added new optional deployment arguments:
       -  `--custom-resource-mode` (default `false`) when set `true` processes custom resources only.
       -  `defined-as3-declaration` for processing user defined AS3 Config Map in CIS watched namespaces.
* CIS Requires AS3 versions >= 3.18 for 2.x releases.
* CIS is now compatible with:
       -   OpenShift 4.3.
       -   BIG-IP 15.1.
       -   K8S 1.18.
* Base image upgraded to UBI for CIS Container images.
* Added Support for:
       -   Multiple BIG-IP ClientSSL profiles for a Virtual Server.
       -   Informer based Override AS3 ConfigMap.
       -   `UserAgent` in AS3 Controls object.
       -   New Attributions Generator  - Licensee.
       -   GO Modules for dependency management.
       -   HTTPS health monitoring for passthrough and re-encrypt routes.
* New RH container registry : registry.connect.redhat.com/f5networks/cntr-ingress-svcs

Bug Fixes
`````````
* CIS handles requests sent to unknown hosts for Routes using debug messages.
* CIS handles posting of 'Overwriting existing entry for backend' log message frequently when different routes configured in different namespaces.
* :issues: 1233 CIS handles ClientSSL annotation and cert/key logging issues.
* :issues: 1145,1185,1295 CIS handles namespace isolation for AS3 configmaps.
* :issues: 1241,1229 CIS fetches 3.18 AS3 schema locally.
* :issues: 1191 CIS cleans AS3 managed partition when moved to CCCL as agent.
* :issues: 1162 CIS properly handles OpenShift Route admit status.
* :issues: 1160 CIS handles https redirection for ingress which accepts all common names.

Vulnerability Fixes
`````````````````````
+------------------+----------------------------------------------------------------+
| CVE              | Comments                                                       |
+==================+================================================================+
| CVE-2009-3555    | CIS disables renegotiation for all Custom ClientSSL            |
+------------------+----------------------------------------------------------------+

Limitations
```````````
* CIS in cccl mode, cannot update OpenShift A/B route in BIGIP >=v14.1.x due to data group changes.

Next Upgrade Notes
``````````````````
* CIS removes additional AS3 managed partition "_AS3" from release 2.1

1.14.0
------------
Added Functionality
`````````````````````
* Added optional command line arguments to support TLS version and Ciphers.
    -  `--tls-version` to enable specific TLS version 1.2/1.3 on BIG-IP. Default 1.2
    -  `--ciphers` to configure cipher suite on BIG-IP. Option valid for TLSv1.2
    -  `--cipher-group` to configure a cipher-group on BIG-IP. Option valid for TLSv1.3
  
  .. note::
     both `--ciphers` and `--cipher-group` are mutually exclusive based on the TLS version.

* Helm charts based `F5 BIG-IP Controller Operator <https://catalog.redhat.com/software/operators/search?p=1&q=f5>`_ published at Redhat Operator Market place.
* Added optional command line argument `--as3-post-delay` to introduce delay in posting AS3 messages to BIG-IP.
* Controller is now compatible with OpenShift version 4.2 and AS3 version 3.17.0.
* CCCL(f5-cccl and f5-ctrlr-agent) and base image packages upgraded from python2.7 to python3.6.

Bug Fixes
`````````
* Controller properly updates Route admit status in OpenShift Dashboard.
* Controller supports update of balance annotation for Routes and Ingress.
* Controller handles edge routes with path configured as "/"(slash).
* Controller incorporates `ASM vulnerability fix <https://support.f5.com/csp/article/K91382300>`_.
* Schema validation failures not observed when AS3 partition deleted.
* Edge redirect routes with WAF policy now works in combination with edge allow routes or insecure routes.
* :issues: 1160 Controller supports HTTPS redirect in ingress when host spec not configured.
* SR - Controller supports `--default-client-ssl` when operating in AS3 mode.

1.13.0
------------
Added Functionality
`````````````````````
* CIS supports Kubernetes 1.16.2.
    - | Update CIS deployment, `apiVersion` to `apps/v1` and add `spec.selector.matchLabels.app` to match `spec.template.metadata.labels.app`.
* Added new command-line options:
      - `--manage-ingress-class-only` A flag whether to handle Ingresses that do not have the class annotation and with annotation `kubernetes.io/ingress.class` set to `f5`. When set `true`, process ingress resources with `kubernetes.io/ingress.class` set to `f5` or custom ingress class.
      - `--ingress-class` to define custom ingress class to watch.
      - `--filter-tenants` A flag whether to enable tenant filtering in BIG-IP.
* CIS pushes AS3 Configuration after 3 seconds when encounters 503 HTTP response code from BIG-IP.
* CIS does not push AS3 configuration when encounters 404 HTTP response code from BIG-IP.

Bug Fixes
`````````
* CIS handles data groups correctly with routes/ingress in multiple namespaces.
* CIS does not allow User Defined Configmap with controller managed partitions as tenants.
* CIS handles HTTP to HTTPS redirect for child paths in routes.
* :issues: 1077 CIS now doesn't post Warning messages 'Overwriting existing entry for backend' frequently.
* :issues: 1014 Fixed performance problem with large number of ingress resources.
* SR - High CPU load in BIG-IP with CIS. CIS doesn’t post data to BIG-IP when there is no change in resources.
* SR - K8S AS3-declaration errors when using TCP-profile. CIS allows TCP profile update using Override ConfigMap.


1.12.0
------------
Added Functionality
`````````````````````
* Support AS3 for BIG-IP orchestration with Kubernetes Ingress.
* Users can override parameters in controller generated AS3 declaration using a new `--override-as3-declaration` option.
* CIS handles URL paths to the nearest matching parent path for OpenShift Routes.
* Added new command-line option `--log-as3-response` to log as3 error response.

Bug Fixes
`````````
* CIS handles the combination of Edge and Re-encrypt OpenShift routes.
* CIS does not send encrypted traffic to Edge Route backend.
* :issues: 1041 CIS now does not log dozens of "INFO" log messages frequently.
* :issues: 931 Issue resolved for the Prometheus metric status="parse-error".

Limitations
```````````
* Master Node label must set to "node-role.kubernetes.io/master=true" when operating on K8S version 1.13.4 or OSCP version 4.1 and above in nodeport mode. If not set, BIG-IP treats master node as any other pool member.
* CIS considers `secure-serverssl` annotation as `true` irrespective of the configuration.
* CIS does not support virtual-server.f5.com/http-port annotation.

v1.11.1
------------
Bug Fixes
`````````
* Controller handles WAF Policy in the root path of a domain in OpenShift Routes.
* Controller handles OpenShift Routes with WAF Policy in multiple namespaces.
* Controller now does not push configuration to BigIP using AS3 for every 30 seconds with no changes.
* :issues: 1041 Controller now does not log dozens of "INFO" log messages frequently.
* :issues: 1040 Controller does not crashes if latest AS3 schema is not available.
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
* :issues: 790 Controller properly handles OpenShift path based routes with TLS.
* :issues: 1016 Controller now logs INFO messages to STDOUT instead of STDERR.
* Controller provides readable help message in logs when ``--router-vserver-addr`` is not configured.

Limitations
```````````
* Limitations for Openshift Routes orchestration through AS3 backend are available `here <https://clouddocs.f5.com/containers/latest/>`_.

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
* Limitations for Openshift Routes orchestration through AS3 backend are available `here <https://clouddocs.f5.com/containers/latest/>`_.

v1.9.2
------------
Bug Fixes
`````````
* Controller handles http redirects without entering into an infinite loop.
* :issues:810 Controller does not delete resources in BIG-IP and recreates during controller pod restart.

v1.9.1
------
Added Functionality
`````````````````````
* Added support for `establishing trust <https://clouddocs.f5.com/containers/latest/userguide/config-parameters.html#as3-parameters>`_ with remote BIG-IP systems using either the device or CA certificates.
* Added support for AS3 3.11.

Bug Fixes
`````````
* Improves performance when updating Configmaps with AS3 Declarations.
* Improves performance when updating Services associated with AS3 Declarations.
* Improves performance when handling changes in Endpoints associated with AS3 Declarations.
* Improves performance when handling node updates in AS3 Declarations.
* Improves performance when applying AS3 Declarations to BIG-IP.
* :issues:797 - Controller uses ``flannel.alpha.coreos.com/public-ip`` as VTEP endpoint.

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
* :issues:736 - Added support for Google Container Engine (GKE) LoadBalancer service. Validated against Kubernetes 1.13.4.

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
* :issues:810 - Controller doesn't delete services and recreates during bigip-ctlr pod restart
* :issues:718 - Namespaces that start with a number does not cause errors

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
* :issues:789 - Controller properly creates https redirect for child paths in k8s Ingress.
* Fixes an issue in openshift where communication breaks with clients with no SNI support.

v1.7.0
------

Added Functionality
```````````````````
* Added `--manage-configmaps` argument to CC to prevent or allow CC to respond to ConfigMap events. Defaults to `true`.
* Added `virtual-server.f5.com/whitelist-source-range` Ingress/Route annotation to support IP CIDR whitelisting.
* :issues:699 - Ability to configure health monitor type in Ingress/Route annotation. Http is the default.
* Changed container base image to use debian-slim.

Bug Fixes
`````````
* :issues:735 - Deleted rules from routes and ingresses on the same service not cleaned up properly.
* :issues:753 - Controller doesn't delete and recreate annotation-based policy rules.
* :issues:755 - Controller implements best-match by setting first-match and sorting rules in reverse lexical order.
* :issues:765 - Controller properly sorts Route rules in reverse lexical order.

v1.6.1
------

Bug Fixes
`````````
* :issues:486 - User cannot configure the controller to manage the Common partition.
* :issues:743 - Controller doesn't temporarily remove entire BIG-IP configs after deleting a single service.
* :issues:746 - Log messages and documentation added to ensure Route profile configuration is clear.

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
* :issues:683 - Controller upgrades properly with new metadata field.
* :issues:686 - Controller in cluster mode does not rely on vxlan name to configure pool members.

v1.5.0
------

Added Functionality
```````````````````
* Support for virtual server source address translation configuration.
* Support for app-root and url-rewrite annotations.
* Added controller name and version to the metadata of certain BIG-IP LTM resources managed by the controller.
* :issues:433 - Support for pre-existing server ssl profiles for Ingresses.
* Added support for attaching OpenShift Routes to existing BIG-IP virtual servers.
* Added support for Kubernetes version 1.8.
* Added support for OpenShift Origin version 3.7.
* Added support for Red Hat OpenShift Container Platform (OSCP) version 3.7.
* (BETA) Added initial basic support for Prometheus metrics.
* `F5 IPAM Controller <https://github.com/F5Networks/f5-ipam-ctlr>`__ pairs with k8s-bigip-ctlr by writing out `virtual-server.f5.com/ip` annotation for IP addresses allocated for host names in Ingresses or ConfigMaps.
* Added support for using `helm`_ to deploy the Controller using the `f5-bigip-ctlr chart`_.
* Added support for using `helm`_ to deploy Ingress resources using the `f5-bigip-ingress chart`_.

Bug Fixes
`````````
* :issues:552 - Controller properly creates Secret SSL profiles for ConfigMaps.
* :issues:592 - Node label selector works properly in cluster mode.
* :issues:603 - Pool only mode no longer prints excessive logs.
* :issues:608 - Single service Ingresses cannot share virtual servers.
* :issues:636 - Controller configures default ssl profiles for Routes when specified via CLI.
* :issues:635 - Controller cleans up policy rules when an Ingress removes them.
* :issues:638 - Ingress extended paths no longer break BIG-IP GUI links.
* :issues:649 - Route annotation profiles are no longer ignored.
* :cccl-issue:214 - Keys and certificates are now installed onto the managed partition.

Limitations
```````````
* Cannot apply app-root and url-rewrite annotations to the same resource; see: :issues:675
* If an older controller created resources, upgrading to the new version could
  result in a python exception when adding metadata to virtuals: :issues:683
* If running the controller in cluster mode without a vxlan name, pool members are not created: :issues:686

v1.4.2
------

Bug Fixes
`````````
* :issues:549 - Using IP annotation on ConfigMaps would result in the virtual server getting a port of 0.
* :issues:551 - Memory leak in python subprocess
* :cccl-issue:211 - Memory leak in f5-cccl submodule
* :issues:555 - Controller high CPU usage when inactive
* :issues:510 - Change behavior of controller on startup when encountering errors
* :issues:567 - Clean up all objects (including iRules and datagroups) when deleting Routes.

v1.4.1
------

Bug Fixes
`````````
* (github-517)Controller deletes SSL profiles off of Ingress virtual servers if watching multiple namespaces.
* (github-471)When updating routes, old service pools are not removed until after a refresh cycle.
* (github-228)Address compatibility for BIG-IP v13.0 Health Monitor interval and timeout.

v1.4.0
------

Added Functionality
```````````````````
* Enhanced route domain handling:

  - Create VxLAN forwarding database (FDB) addresses for route domains.
  - Ability to change the default route domain for a partition managed by an F5 controller after the controller has deployed.

* Support for `Flannel VxLAN in Kubernetes <https://clouddocs.f5.com/containers/latest/>`_.
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
* (github-341)HTTPS redirect applies to individual Routes instead of all Routes.
* (github-344)Create default for SNI profile when using Ingress custom profiles from Secrets.
* (github-460)Remove risk that pools will update with wrong members after a node update (NodePort mode).
* (github-428)Controller writes unnecessary updates when no config changes occurred.
* (github-506)Controller stops updating BIG-IP after an exception occurs in the python driver.
* (github-198)Corrected a comparison problem in CCCL that caused unnecessary updates for BIG-IP Virtual Server resources.

Limitations
```````````
* If you are deploying services using the F5-supported iApps, you must upgrade to a version that supports
  route domain 0 for non-Common partitions. The minimum versions required for the F5 iapps are:

  - f5.http: ``f5.http.v1.3.0rc3``
  - f5.tcp: ``f5.tcp.v1.0.0rc3``

  You can find these versions in the iapp package ``iapps-1.0.0.492.0``. To upgrade, you must perform the following:

  - Download and install the latest iApps templates `iApps`_.
  - Set the service to use the newer iApp template `iApps`_.

* Check BIG-IP version compatibility on Application Services (iApps) before deploying. See Application Services Integration iApp.
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
  See `Replace the OpenShift F5 Router with the BIG-IP Controller <https://clouddocs.f5.com/containers/latest/>`_ for more information.

Bug Fixes
`````````
* Properly configure http redirect rules on v11.6.1 BIG-IP systems.
* Failed configurations for objects do not prevent future configurations from happening.

Limitations
```````````

* OpenShift - (github-341)Does not currently support redirect for individual Routes. If a Route specifies
  "insecureEdgeTerminationPolicy" as "Redirect", the http virtual server will enable this policy for all Routes.

v1.1.1
------

Bug Fixes
`````````
* (github-311)Fix SIGSEV on non-"f5" valued class annotation.
* (github-288)Remove default pool for Ingress and Routes.

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
