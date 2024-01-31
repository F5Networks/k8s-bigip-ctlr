
## Pool Member Type - auto
If deployment is configured with the auto mode, CIS will auto learn the service type and populate the bigip pool members based on the service types

## Configuration
```
   args:
     --pool-member-type=auto
```

# Supported Services
CIS in auto mode will auto learn the service types and process the pool members. Below service types are supported 
with the respective pool member types

| CIS version | Service Type             | Pool Members | VXLan Required                          |
|-------------|--------------------------|-------------|-----------------------------------------|
| 2.16+       | ClusterIP                | Pod IPs     | Yes(If static routing Mode not enabled) |
| 2.16+       | NodePort                 | Node IP's   | N/A                                     |
| 2.16+       | LoadBalancer             | Node IP's   | N/A                                     |

  
**Note:** 

* In auto pool mode & static routing mode disabled, to enable traffic to cluster type services(pods), vXlan config is required
* For Headless service - Service Type will be ClusterIP. So pod IPs will be configured on the BIG IP

