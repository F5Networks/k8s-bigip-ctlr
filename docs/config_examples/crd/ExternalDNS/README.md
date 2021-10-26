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


## externaldns-tcp-monitor.yaml

By deploying this yaml file in your cluster, CIS will create a edns containing GSLB pool health monitored on BIG-IP.