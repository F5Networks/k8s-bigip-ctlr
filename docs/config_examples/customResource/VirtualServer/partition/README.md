# Virtual Server with partition

This section demonstrates the option to configure partition in virtual server.

Option which can be used to partition:

```
partition:
```
* Create Virtual Server on the respective partition on BIG-IP

```
#Example
partition: dev
```

## vs-with-partition.yaml

By deploying this yaml file in your cluster, CIS will create Virtual Server in dev partition on BIG-IP
