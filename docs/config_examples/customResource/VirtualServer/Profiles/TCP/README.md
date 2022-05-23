# Virtual Server with Profile TCP

This section demonstrates the option to configure Profile TCP in virtual server.

Option which can use to refer Profile TCP:

```
#Example
profiles:
 tcp:
   client: /Common/f5-tcp-lan
   server: /Common/f5-tcp-wan
```

## vs-with-profileTCP.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing Profile TCP on BIG-IP.
