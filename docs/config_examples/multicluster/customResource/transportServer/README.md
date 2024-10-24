# Unsecured Transport Server


## Weight support in Active-Active, Active-Passive and ratio mode
In multi cluster Active-Active, Active-Passive or ratio mode, weight is supported with local, alternate and extended services.
CIS process the weight and populate each pool member on the bigIP with the specific ratio.
This allows to distribute specific percentage of traffic to a specific service and cluster.


`config`

```
multiClusterServices:
  - clusterName: cluster3
    namespace: default
    service: svc-1-external-service
    servicePort: 1344
    weight: 70
  - clusterName: cluster4
    namespace: default
    service: svc-1-external-service
    servicePort: 1344
    weight: 70
```


**Note:**
* In Active-Active or Active-Passive mode, CIS populates the bigIP with pool members with the weights specified for each pool
* In Ratio mode CIS calculates ratio of each member by taking cluster ratio and service ratio into consideration
* Unlike VS, transport server supports alternate backend and external services(all modes) with single pool.
* To support alternate backend with transport server, CIS by default configures load balancing method to "ratio(member)" at pool level
  