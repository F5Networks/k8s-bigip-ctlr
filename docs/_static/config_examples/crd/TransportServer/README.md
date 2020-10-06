# Unsecured Transport Server

This section demonstrates the deployment of unsecured Transport Servers.

CIS VirtualServer CRD implements a full proxy architecture for virtual servers configured with a HTTP profile allowing Layer 7 load balancing and SSL processing. User may able to expose non-http traffic such as databases via CIS using Transport Server CRD.

## transport-server.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP "172.16.3.9" and port "8544". 
It will forward traffic to specified pool.