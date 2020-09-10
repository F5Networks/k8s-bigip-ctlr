# Health Monitor

This section demonstrates the option to configure health monitor for pools in virtual server.
Heath monitor is supported for each pool members. 

Option which can be use to configure health monitor:

```
monitor:
    type: 
    send: 
    recv:
    interval: 
    timeout: 
```
* type, send and interval are required fields.

## health-monitored-pool-virtual-server.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing health monitored pool on BIG-IP.