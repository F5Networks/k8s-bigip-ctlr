# Virtual Server AlternateBackend Support

This section demonstrates the option to configure virtual server Alternate Backends.

Option which can be used to configure is :
```
alternateBackends:
- service: svc-2
  weight: 30
  serviceNamespace: default
```

## virtual-with-ab.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP as with alternatebackend pools and traffic is distributed based on weights.

## Creating the kubernetes secrets with certificates for BIG IP

```shell
kubectl create secret tls <secret-name> --cert=<path/to/certificate.crt> --key=<path/to/private.key> -n <namespace>
```
