# TLS Options in TLSProfile

This example shows how to configure TLS options like `no-dtls` and `single-dh-use` in a TLSProfile CRD. These options are applicable to both client and server SSL profiles.

Apply the TLSProfile:

kubectl apply -f virtualserver-with-tlsOptions-no-dtls-single-dh-use.yml

```yaml
   clientSSLParams:
      dtlsEnabled: false # enables no-dtls option on bigip profile
      singleUseDhEnabled: true # enables single-dh-use option on bigip profile
  clientSSLs:
   - foo-secret
  reference: secret
  serverSSLParams:
      dtlsEnabled: false
      singleUseDhEnabled: true
  serverSSLs:
    - foo-back-secret

```

