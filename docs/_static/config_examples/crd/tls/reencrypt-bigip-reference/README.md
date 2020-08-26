# Secure Virtual Server with Re-encrypt Termination using BIG-IP Profiles

This section demonstrates the deployment of a Secure Virtual Server with Re-encrypt Termination using BIG-IP Profiles.

## virtualserver.yml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP "172.16.3.5". 
It will load balance the traffic for domain coffee.example.com

## reencrypt-tls.yml

By deploying this yaml file in your cluster, CIS will attach /Common/clientssl as clientssl and /Common/serverssl as serverssl 
for above Virtual Server with VIP "172.16.3.5".  