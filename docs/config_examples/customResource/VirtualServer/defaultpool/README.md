# Virtual Server with default pool

This section demonstrates the option to configure default pool in virtual server.

Example for defaultPool with service:

```
  defaultPool:
    reference: service
    service: svc-1
    serviceNamespace: default
    servicePort: 80
    monitors:
    - interval: 10
      recv: a
      send: /
      timeout: 10
      type: http
```

Example for defaultPool with existing pool:

```
  defaultPool:
    reference: bigip
    name: /Common/defaultpool
```




* Attach a default pool to the virtual server.


## vs-with-defaultPool.yaml
By deploying this yaml file in your cluster, CIS will attach a default pool to the virtual server on BIG-IP.
