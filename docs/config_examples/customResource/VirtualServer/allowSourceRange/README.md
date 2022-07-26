# Virtual Server with AllowSourceRange

This section demonstrates the option to configure AllowSourceRange in virtual server.

Option which can be use to AllowSourceRange:

```
allowSourceRange:
```
* Creates a Rule in policy with allowSourceRange on BIG-IP to reference it here.

```
#Example
allowSourceRange: [1.1.1.0/24]
```

## vs-with-allowSourceRange.yaml

By deploying this yaml file in your cluster, CIS will create a policy resource with  allowSourceRange rule
on BIG-IP.
