# Virtual Server with profileAccess and policyPerRequestAccess

This section demonstrates the option to configure access profile and per request policy in virtual server.

Option which can use to refer profileAccess & policyPerRequestAccess :

`Example`

```
profileAccess: /Common/prof-access
policyPerRequestAccess: /Common/per-req-pol
```

## access-profile-per-reqeust-policy.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing access profile and per request policy on BIG-IP.
