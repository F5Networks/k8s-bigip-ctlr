# Ingress Link with partition

This section demonstrates the option to configure partition in Ingress Link.

Option which can be used to partition:

```
partition:
```
* Create Ingress Link on the respective partition on BIG-IP

```
#Example
partition: dev
```

## ingresslink-with-partition.yaml

By deploying this yaml file in your cluster, CIS will create Ingress Link VS in dev partition on BIG-IP
