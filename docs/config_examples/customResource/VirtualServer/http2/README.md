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
#3
profiles:
  http2: 
    client: /Common/samplehttp2Client
    server: /Common/samplehttp2server
```

## vs-with-profilehttp2.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server containing http2 Profile on BIG-IP.
Here client corresponds to ingress http2 profile and Server refers to egress http2 profile.
