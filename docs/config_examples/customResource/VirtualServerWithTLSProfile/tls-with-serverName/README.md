# Server Name on Custom Server SSL Profiles created by CIS through secrets

## tls-server-ssl-secrets-serverName.yml

By deploying this yaml file in your cluster, CIS will create custom SSL profiles with server name for TLS Client on BIG-IP.

## virtualserver.yml
By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP "172.16.3.5".
It will load balance the traffic for domain coffee.example.com

## Creating the kubernetes secrets with certificates for BIG IP

```shell
kubectl create secret tls <secret-name> --cert=<path/to/certificate.crt> --key=<path/to/private.key> -n <namespace>
```
