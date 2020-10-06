# Create a simple HTTP Virtual Server without Host parameter.

This section demonstrates the deployment of a Basic Virtual Server without Host Parameter.

## noHost-single-pool-virtual.yml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP "172.16.3.4" and attaches a policy which forwards the traffic to pool svc-1 when the uri path segment is /coffee.   

Note: This is an insecure virtual, Please use TLSProfile to secure the virtual.
check out tls examples to understand more.