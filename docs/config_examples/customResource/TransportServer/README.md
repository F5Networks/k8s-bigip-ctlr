# Unsecured Transport Server

This section demonstrates the deployment of unsecured Transport Servers.

CIS VirtualServer CRD implements a full proxy architecture for virtual servers configured with a HTTP profile allowing Layer 7 load balancing and SSL processing. User may able to expose non-http traffic such as databases via CIS using Transport Server CRD.

## TCP Transport Server

* TCP mode is the default type of transport server. 
* By deploying `tcp-transport-server.yaml` yaml file in your cluster, CIS will create a TCP Virtual Server on BIG-IP with VIP "172.16.3.9" and port "8544". It will forward traffic to specified pool.

### Health Monitor

This section demonstrates the option to configure health monitors for pools in a transport server of type TCP.
You can define the health monitors for each pool members as follows:

#### Single Health Monitor

Option which can be used to configure health monitor:

type `tcp` monitor
```
monitor:
    type: 
    interval: 
    timeout: 
    targetPort:
```
* type and interval are required fields.


#### Multiple Health Monitors

You can also provide multiple health monitors for your TS CR as follows:
```
monitors:
-   type: 
    targetPort:
    interval: 
    timeout:
-   type: 
    interval: 
    timeout: 
```
Note: **monitors** take priority over **monitor** if both are provided in TS spec.

#### Referencing existing BIG- IP health monitors

You can also create a health monitor in BIG IP and reference it in your TS Spec as follows:

* Using monitor in spec
```
monitor:
    name: 
    reference: 
```

* Using monitors in spec
```
monitors:
-   name:
    reference:
-   type: 
    interval:
    targetPort: 
    timeout:
-   type: 
    interval: 
    timeout: 
```

## UDP Transport Server

* For UDP type transport servers, yaml spec should contain a `type` parameter. Refer `udp-transport-server.yaml` example for more details
* By deploying `udp-transport-server.yaml` yaml file in your cluster, CIS will create a UDP Virtual Server on BIG-IP with VIP "172.16.3.10" and port "8444". It will forward traffic to specified pool.

## SCTP Transport Server

* For SCTP type transport servers, yaml spec should contain a `type` parameter. Refer `sctp-transport-server.yaml` example for more details
* By deploying `sctp-transport-server.yaml` yaml file in your cluster, CIS will create a SCTP Virtual Server on BIG-IP with VIP "10.8.3.12" and port "30102". It will forward traffic to specified pool.
