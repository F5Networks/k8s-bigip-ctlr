# Transport Server with partition

This section demonstrates the option to configure partition in transport server.

Option which can be used to partition:

```
partition:
```
* Create Transport Server on the respective partition on BIG-IP

```
#Example
partition: dev
```

## ts-with-partition.yaml

By deploying this yaml file in your cluster, CIS will create Transport Server in dev partition on BIG-IP
