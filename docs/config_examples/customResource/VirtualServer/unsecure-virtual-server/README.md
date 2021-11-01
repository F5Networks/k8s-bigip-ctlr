# UnSecure Virtual Server

This section demonstrates the deployment of unsecured Virtual Servers.

## example-single-pool-virtual.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP "172.16.3.4". 
It will load balance the traffic for domain cafe.example.com

## example-two-pool-two-virtual.yaml

By deploying this yaml file in your cluster, CIS will create two Virtual Servers on BIG-IP with VIP "172.16.3.4" and "172.16.3.5".
Former will load balance the traffic for domain coffee.example.com and later will load balance the traffic for domain tea-virtual-server
