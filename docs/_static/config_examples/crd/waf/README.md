# Virtual Server with WAF

This section demonstrates the option to configure WAF policy in virtual server.

Option which can be use to WAF:

```
waf:
```
* First create WAF policy on BIG-IP to reference it here. 

```
#Example
waf: "/Common/waf_policy"
```

## vs-with-waf.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing WAF policy on BIG-IP.