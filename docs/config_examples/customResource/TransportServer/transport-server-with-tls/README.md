# Transport server with TLS
This section demonstrates the option to configure TLS in transport server.

Option which can be used is:
```
tls:
    clientSSLs:
    -
    serverSSLs:
    -
    reference:
```

## ts-with-tls-bigip-ref.yaml

By deploying this yaml file in your cluster, CIS will create a transport server with BIGIP TLS Configuration.

## ts-with-tls-secret-ref.yaml

By deploying this yaml file in your cluster, CIS will create a transport server with k8s Secret TLS Configuration.
