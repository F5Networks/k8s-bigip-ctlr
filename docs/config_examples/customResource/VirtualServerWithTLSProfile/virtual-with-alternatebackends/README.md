# Virtual Server AlternateBackend Support

This section demonstrates the option to configure virtual server Alternate Backends.

Option which can be used to configure is :
alternateBackends:
- service: svc-2
  weight: 30
  serviceNamespace: default

## virtual-with-ab.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP as with alternatebackend pools and traffic is distributed based on weights.