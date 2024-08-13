# Virtual Server with Adapt Profile

This section demonstrates the option to configure Adapt Profile in virtual server.

Option which can be used to refer Adapt Profile:

```
#Example
profileAdapt:
  request: /Common/example-requestadapt
  response: /Common/example-responseadapt
```

## vs-with-adaptProfile.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing request and response adapt Profiles on BIG-IP.
