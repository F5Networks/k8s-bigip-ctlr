# Unsecured Transport Server

This section demonstrates the deployment of unsecured Transport Servers.

CIS VirtualServer CRD implements a full proxy architecture for virtual servers configured with a HTTP profile allowing Layer 7 load balancing and SSL processing. User may able to expose non-http traffic such as databases via CIS using Transport Server CRD.

## TCP Transport Server

* TCP mode is the default type of transport server. 
* By deploying `tcp-transport-server.yaml` yaml file in your cluster, CIS will create a TCP Virtual Server on BIG-IP with VIP "172.16.3.9" and port "8544". It will forward traffic to specified pool.

## UDP Transport Server

* For UDP type transport servers, yaml spec should contain a `type` parameter. Refer `udp-transport-server.yaml` example for more details
* By deploying `udp-transport-server.yaml` yaml file in your cluster, CIS will create a UDP Virtual Server on BIG-IP with VIP "172.16.3.10" and port "8444". It will forward traffic to specified pool.
