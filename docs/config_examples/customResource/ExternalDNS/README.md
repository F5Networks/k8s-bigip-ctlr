# ExternalDNS

ExternalDNS CRD's allows you to control DNS records dynamically via Kubernetes/OSCP resources in a DNS provider-agnostic way. 

Configure health monitor for GSLB pools in DNS.
Heath monitor is supported for each pool members. 

Option which can be use to configure health monitor:

type `http` and `https` monitors
```
monitor:
    type: 
    send: 
    recv:
    interval: 
    timeout: 
```
* type, send and interval are required fields.


type `tcp` monitor
```
monitor:
    type: 
    interval: 
    timeout: 
```
* type and interval are required fields.


## Multiple Health Monitors

You can also provide multiple health monitors for your Wide IP as follows:
```
monitors:
-   type: 
    send: 
    recv:
    interval: 
    timeout:
-   type: 
    send: 
    recv:
    interval: 
    timeout: 
```
Note: **monitors** take priority over **monitor** if both are provided in edns spec.
## externaldns-tcp-monitor.yaml

By deploying this yaml file in your cluster, CIS will create a edns containing GSLB pool health monitored on BIG-IP.

## externaldns-pool-priority-order.yaml

When the load balancing method is set to Global Availability, BIG-IP GTM distributes DNS name resolution requests to the first available virtual server in a pool. BIG-IP GTM starts at the top of a manually configured list of virtual servers and sends requests to the first available virtual server in the list. Only when the virtual server becomes unavailable does BIG-IP GTM send requests to the next virtual server in the list. Over time, the first virtual server in the list receives the most requests and the last virtual server in the list receives the least requests.

To set this option on BIG-IP using CIS, in the EDNS resource spec, 
* Set the load balancing method to `global-availability`.
* Configure the priority order of pool members using `spec.pools[].order`. All the distributed wideIP pools need to have correct pool order.
