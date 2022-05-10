# Virtual Server with OneConnect

This section demonstrates the option to configure OneConnect profile in virtual server.

Option which can be use to OneConnect:

```
profileMultiplex:
```
* First create OneConnect profile on BIG-IP to reference it here.

```
#Example
profileMultiplex: "/Common/oneconnect"
```

## vs-with-oneConnect.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing OneConnect profile
on BIG-IP.
