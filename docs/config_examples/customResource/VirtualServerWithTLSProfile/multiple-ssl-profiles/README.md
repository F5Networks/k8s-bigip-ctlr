# Secure Virtual Server with multiple ssl profiles and kuberentes secrets

This section demonstrates the deployment of a Secure Virtual Server with Re-encrypt Termination using BIGIP Profiles and kubernetes secrets.

## virtualserver.yml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP "172.16.3.5". 
It will load balance the traffic for domain coffee.example.com

## multiple-bigip-ssl-profiles.yml

By deploying this yaml file in your cluster, CIS will attach /Common/clientssl and /Common/foo-clientssl as clientssl and /Common/serverssl and /Common/foo-serverssl as serverssl 
for above Virtual Server with VIP "172.16.3.5".

## multiple-kubernetes-ssl-secrets.yml  
By deploying this yaml file in your cluster, CIS will attach k8s secrets clientssl-secret1 and clientssl-secret2 as client SSL profile & k8s secrets  serverssl-secret1 and serverssl-secret2 as client SSL profile for VIP "172.16.3.5".

Note:- You need deploy either "multiple-bigip-ssl-profiles.yml" or "multiple-kubernetes-ssl-secrets.yml" with "virtualserver.yml".

## Creating the kubernetes secrets with certificates for BIG IP

```shell
kubectl create secret tls <secret-name> --cert=<path/to/certificate.crt> --key=<path/to/private.key> -n <namespace>
```
