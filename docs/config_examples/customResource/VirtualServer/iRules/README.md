# Virtual Server with Custom iRules 

This section demonstrates the option to configure custom IRules in virtual server.

Option which can use to refer custom iRules:

```
#Example
iRules: 
- /Common/secureiRule
- /Common/customiRule
```

## vs-with-iRules.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing custom iRules on BIG-IP.
