# Health Monitor

This section demonstrates the option to configure health monitors for pools in a virtual server.
You can define the health monitors for each pool members as follows:

## Single Health Monitor

Option which can be used to configure health monitor:

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

You can also provide multiple health monitors for your VS CR as follows:
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
Note: **monitors** take priority over **monitor** if both are provided in VS spec.

## Referencing existing BIG- IP health monitors

You can also create a health monitor in BIG IP and reference it in your VS Spec as follows:

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

### health-monitored-pool-virtual-server.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing health monitored pool on BIG-IP.

Option which can be used to link existing health monitor on bigip:
```
monitor:
    name: 
    reference: 
```
* name - name of monitor existing on bigip in the format `/<partition>/<monitor_name>` eg: `/Common/custom-http-monitor`
* reference - This should be set as `bigip` to reference existing health monitor.

### Custom-health-monitor-virtual-server.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server referencing health monitor existing on BIG-IP.


