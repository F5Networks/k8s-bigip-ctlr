# Secure Virtual Server with Re-encrypt Termination using BIG-IP Profiles

This section demonstrates the option to configure VirtualAddress port number. This is required to use the same VIP with different port number for different domains.

Two options which can be used to configure are :
    1. virtualServerHTTPPort
    2. virtualServerHTTPSPort

## custom-http-port.yml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP custom http  port as 500 
It will load balance the traffic for domain cafe.example.com

## custom-https-port.yml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP custom https port as 500 
It will load balance the traffic for domain cafe.example.com
