# Unsecured Transport Server

This section demonstrates the deployment of unsecured Transport Servers.

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
```
* type and interval are required fields.

## UDP Transport Server

* For UDP type transport servers, yaml spec should contain a `type` parameter. Refer `udp-transport-server.yaml` example for more details
* By deploying `udp-transport-server.yaml` yaml file in your cluster, CIS will create a UDP Virtual Server on BIG-IP with VIP "172.16.3.10" and port "8444". It will forward traffic to specified pool.
