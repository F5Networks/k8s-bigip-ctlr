# Single Domain with combination of Edge and Re-encrypt termination

This section demonstrates the deployment of two Virtual Servers one with Edge Termination and other with Re-encrypt Termination.
Both the Virtual Servers refer same domain[tea.example.com].

## tea-virtual-server_edge.yml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP "172.16.3.4". 
It will load balance the traffic for service svc-edge on domain tea.example.com

## tea-virtual-server_reen.yml

By deploying this yaml file in your cluster, CIS will update Virtual Server on BIG-IP with VIP "172.16.3.4". 
It will load balance the traffic for service svc-1 and svc-2 on domain tea.example.com

## reencrypt-tls.yml

By deploying this yaml file in your cluster, CIS will attach k8s secrets[clientssl and serverssl] as client and server
profiles for VIP "172.16.3.4". 

This is only applicable for services svc-1 and svc-2

## edge-tls.yml

By deploying this yaml file in your cluster, CIS will attach k8s secret[clientssl] as client profile for VIP "172.16.3.4". 

This is only applicable for services svc-edge

## Note: clientssl mentioned in both edge-tls.yml and reencrypt-tls.yml should be same as both are pointing to same domain.