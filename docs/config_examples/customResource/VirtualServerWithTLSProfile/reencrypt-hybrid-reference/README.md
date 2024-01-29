# Secure Virtual Server with Re-encrypt Termination using mix of k8s secret and BIGIP Profile

This section demonstrates the deployment of a Secure Virtual Server with Re-encrypt Termination using mix of k8s secret and BIGIP Profile for clientSSL and serverSSL profiles.

# Configuration
  spec:
    tls:
      reference: hybrid
      clientSSLParams:
        profileReference: secret
      serverSSLParams:
        profileReference: bigip

# virtualserver.yml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with VIP "10.8.3.11".
It will load balance the traffic for domain foo.com

# reencrypt-tls.yml

By deploying this yaml file in your cluster, CIS will attach profile created from foo-secret as clientssl and /Common/serverssl as serverssl profiles.
