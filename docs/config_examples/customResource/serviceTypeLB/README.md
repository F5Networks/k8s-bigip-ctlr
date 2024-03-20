# ServiceType LoadBalancer with Multiport Support

This section demonstrates the option to configure Multiport using ServiceType LoadBalancer.


## multiport-serviceTypeLB.yaml

By deploying this yaml file in your cluster, CIS will create two Virtual Servers with different ports on BIG-IP.

# Health Monitor

This section demonstrates the option to configure health monitor for pools in virtual server.
Health monitor is supported for each pool members.

Options which can be used to configure health monitor:

```
monitor:
    interval: 
    timeout: 
```
* interval is a required field.

## healthMonitor-serviceTypeLB.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing health monitored pool on BIG-IP.

## Static IP support

Service type LB is supported with the static ip configuration. This should be configured in the annotation "cis.f5.com/ip" as below

```
metadata:
  annotations:
    cis.f5.com/ip: 10.8.3.1
```

If IPAM label and static ip are configured in the annotation, cis will consider static ip annotation with high precedence than IPAM label