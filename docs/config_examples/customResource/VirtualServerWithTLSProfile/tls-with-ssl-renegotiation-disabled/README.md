# Disable Renegotiation on Custom SSL Profiles created by CIS through secrets

## tls-ssl-secrets-renegotiation-disabled.yml

By deploying this yaml file in your cluster, CIS will create custom SSL profiles with renegotiation disabled on BIG-IP.

## virtualserver.yml
By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP "172.16.3.5".
It will load balance the traffic for domain coffee.example.com
