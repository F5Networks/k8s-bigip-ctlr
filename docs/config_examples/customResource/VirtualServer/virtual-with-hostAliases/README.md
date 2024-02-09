# Virtual Server with Host Aliases

This section demonstrates the option to configure virtual server using Host Aliases. 
HostAliases is used to specify additional host names for a virtual server apart from the primary host.
This is useful when you want to use a single virtual server to serve multiple domains and forward traffic 
to the same pools.

## tls-with-multiple-hosts.yaml
By deploying this yaml file in your cluster, CIS will create a TLSProfile with multiple domain name.

## virtual-with-hostAliases.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server on BIG-IP with multiple hosts or host aliases.

## Recommendations
- Provide the same host names in TLSProfile as provided in the Virtual Server CR.

## Example showing the Virtual Server CR with Host Aliases and Primary Host
```
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  labels:
    f5cr: "true"
  name: cr-vs-foo-svc-1
  namespace: default
spec:
  allowVlans: []
  host: foo.com  <--------------- Primary Host
  hostAliases: <----------------- Host Aliases
    - dr.foo.com
  httpTraffic: none
  iRules: []
  pools:
    - monitor:
        interval: 20
        recv: ""
        send: /
        timeout: 10
        type: http
      path: /foo
      service: svc-1
      servicePort: 80
  snat: auto
  tlsProfileName: cr-tls-foo-svc-1
  virtualServerAddress: 10.8.0.252
```
