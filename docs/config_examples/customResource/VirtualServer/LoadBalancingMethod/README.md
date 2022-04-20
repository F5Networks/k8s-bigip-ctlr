# Virtual Server with Persistence Profile

This section demonstrates the option to configure LoadBalancingMethod for pools in virtual server.

Option which can use to refer loadBalancingMethod:

```
#Example
loadBalancingMethod: fastest-node
```

## vs-with-LoadBalancingMethod.yaml

By deploying this yaml file in your cluster, CIS will create LTM resources containing Pool with loadBalancingMethod as "fastest-node" on BIG-IP.
