## Weight and Alternate Backend support with transport server

CIS supports a/b with the alternate backed. Weight can be specified for default service and alternate backend service

`config`

```
  pool:
    alternateBackends:
      - service: svc-1-external-service
        serviceNamespace: default
        weight: 20
    extendedServiceReferences:
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
    monitor:
      interval: 20
      timeout: 10
      type: udp
    service: pytest-svc-1
    servicePort: 1344
    weight: 20
```


**Note:**
* Unlike VS, transport server supports alternate backend with single pool. 
* To support alternate backend with transport server, CIS by default configures load balancing method to "ratio(member)" at pool level
  