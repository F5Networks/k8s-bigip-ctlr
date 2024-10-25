# Virtual Server with http2 Profile

This section demonstrates the option to configure http2 Profile in virtual server.

Option which can use to refer http2 Profile:

```
#Examples
#1
profiles:
  http2: 
    client: /Common/samplehttp2Client

#2
profiles:
  http2: 
    server: /Common/samplehttp2server
```
**Note:**
1. Currently, AS3 supports setting either client or server http2 profile on virtual server but doesn't allow both.See [here](https://github.com/F5Networks/f5-appsvcs-extension/issues/793)
2. Renegotiation must be disabled on client/server ssl profiles attached to virtual server before configuring http2 client/server profile on virtual server.
3. If you are using http2 server profile on virtual server, then you must enable httpMrfRoutingEnabled on virtual server for successful HTTP/2 full-proxy deploymen.For More details refer _https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/big-ip-http2-full-proxy-configuration-14-1-0/01.html_

## tls-ssl-secrets-renegotiation-disabled.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing client and server ssl profiles on BIG-IP with renegotiation disabled. 

## vs-with-client-profilehttp2.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing client http2 Profile on BIG-IP.

## vs-with-server-profilehttp2.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing server http2 Profile on BIG-IP.
Here client corresponds to ingress http2 profile and Server refers to egress http2 profile.
