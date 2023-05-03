# Virtual Server with LTM Policy WAF

This section demonstrates the option to configure WAF based pool in virtual server.

Option which can use to refer WAF based pool:

```
#Example
waf: "/Common/WAF_Policy1"
```

## vs-with-waf-based-pool.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing LTM Policy with WAF on BIG-IP.
