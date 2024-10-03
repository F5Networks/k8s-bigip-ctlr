# ServiceType LoadBalancer Support

This section demonstrates the option to configure ServiceType LoadBalancer to be used as Transport server.

## example-service-type-lb.yaml.yaml

By deploying this yaml file in your cluster, CIS will create a Transport Server using the options configured in the svcTypeLB on BIG-IP.

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