# Configure SSL options in TLSProfile CR

This section demonstrates how to Configure ssl options and Cipher options

```
tlsVersion =>	Configures TLS version to be enabled on BIG-IP. TLS 1.3 is only supported on TMOS version 14.0+.
ccipherGroup => Configures a cipher group in BIG-IP and reference it here. Cipher group and ciphers are mutually exclusive, only use one.
ciphers	=> Configures a ciphersuite selection string. Cipher-group and ciphers are mutually exclusive, only use one.
disableTLSVersions	=> Configures to disable a particular version of TLS version on the bigip. Supported values are [1.0, 1.1, 1.2, 1.3]

*Example for TLS_Version: 1.3*
tlsCipher: 
  tlsVersion: "1.3"
  cipherGroup: /Common/f5-default
  disableTLSVersions:
  - "1.2"
Note: cipherGroup property is only considered for tlsVersion 1.3

*Example for TLS_version: 1.2*
tlsCipher: 
  tlsVersion: "1.2"
  ciphers: DEFAULT
  disableTLSVersions:
  - "1.1"
Note: ciphers property is only considered for tlsVersion <= 1.2

NOTE: ssl options (tlsVersion, cipher and cipherGroup) in TLSProfile CR will take precedence over BaseRouteConfig using configmap.
```