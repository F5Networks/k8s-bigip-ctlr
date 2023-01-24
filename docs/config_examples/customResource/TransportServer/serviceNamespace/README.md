# Transport Server with partition

This section demonstrates the option to configure serviceNamespace in transport server.

Option which can be used to serviceNamespace:

```
serviceNamespace:
```
* Namespace of service, Use if service is present in a namespace other than the one where transport Server Custom Resource is present

```
#Example
serviceNamespace: test
```

## ts-with-serviceNamespace.yaml

By deploying this yaml file in your cluster, CIS Transport Server will use the service named "pytest-svc-1" in namespace "test" as pool member
