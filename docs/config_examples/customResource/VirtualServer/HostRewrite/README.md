# Host Rewrite (hostRewrite)
Rewriting the host in HTTP Header of a request before submitting to the pool

Option which can be used for host rewrite

```
hostRewrite:
```
## Example
```
---
  pools:
    - path: /lab
      service: svc-1
      servicePort: 80
      hostRewrite: lab.internal.org
```

## virtual-server.yaml
By deploying this yaml file in your cluster, CIS Virtual Server will rewrite the host header as follows:
 * For request "college.example.org/lib" from "college.example.org" to "lib.internal.org".
 * For request "college.example.org/lab" from "college.example.org" to "lab.internal.org".