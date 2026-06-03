# Protocol Inspection Profile in VirtualServer CRD

This document describes how to configure Protocol Inspection Profiles directly in VirtualServer Custom Resource Definition (CRD) for F5 Container Ingress Services (CIS).

## Overview

Protocol Inspection Profiles enable deep packet inspection capabilities on F5 BIG-IP systems to analyze and control network traffic based on application protocols. VirtualServer CRD allows you to configure protocol inspection profiles directly for HTTP/HTTPS virtual servers.

## Configuration

### Basic VirtualServer with Protocol Inspection

Configure protocol inspection directly in VirtualServer specs:

```yaml
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: my-virtualserver
  namespace: default
spec:
  host: example.com
  virtualServerAddress: "10.192.75.108"
  profiles:
    profileProtocolInspection: "/Common/protocol_inspection_profile"
  pools:
  - path: /
    service: web-service
    servicePort: 80
```

### VirtualServer with Multiple Profiles

Combine protocol inspection with other profiles:

```yaml
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: secure-web-app
  namespace: default
spec:
  host: secure.example.com
  virtualServerAddress: "10.192.75.110"
  profiles:
    profileProtocolInspection: "/Common/web_security_profile"
    tcp:
      client: "/Common/tcp-wan-optimized"
      server: "/Common/tcp-lan-optimized"
    http: "/Common/http-custom"
  pools:
  - path: /api
    service: api-service
    servicePort: 8080
  - path: /
    service: web-service
    servicePort: 80
```

### HTTPS VirtualServer with Protocol Inspection

Configure protocol inspection for HTTPS services:

```yaml
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: https-secure-app
  namespace: default
spec:
  host: https.example.com
  virtualServerAddress: "10.192.75.111"
  tlsProfileName: "reencrypt-tls"
  profiles:
    profileProtocolInspection: "/Common/https_security_profile"
  pools:
  - path: /secure
    service: secure-service
    servicePort: 443
```

## Policy Integration

### VirtualServer with Policy Override

When using policies, VirtualServer profiles take precedence:

```yaml
apiVersion: cis.f5.com/v1
kind: Policy
metadata:
  name: base-security-policy
  namespace: default
spec:
  profiles:
    profileProtocolInspection: "/Common/default_security_profile"

---
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: custom-security-app
  namespace: default
spec:
  host: custom.example.com
  virtualServerAddress: "10.192.75.112"
  policyName: base-security-policy
  profiles:
    profileProtocolInspection: "/Common/custom_security_profile"  # Overrides policy
  pools:
  - path: /
    service: web-service
    servicePort: 80
```

## Complete Production Example

Real-world VirtualServer with comprehensive security:

```yaml
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: production-web-app
  namespace: production
spec:
  host: app.production.com
  virtualServerAddress: "10.192.75.113"
  virtualServerHTTPPort: 80
  virtualServerHTTPSPort: 443
  tlsProfileName: "production-tls"
  httpTraffic: redirect
  profiles:
    profileProtocolInspection: "/Common/production_security_profile"
    tcp:
      client: "/Common/tcp-mobile-optimized"
      server: "/Common/tcp-lan-optimized"
    http: "/Common/http-compression"
  waf: "/Common/production-asm-policy"
  pools:
  - path: /api/v1
    service: api-v1-service
    servicePort: 8080
    waf: "/Common/api-security-policy"
  - path: /api/v2
    service: api-v2-service
    servicePort: 8081
  - path: /static
    service: static-service
    servicePort: 80
  - path: /
    service: web-service
    servicePort: 80
```

## Advanced Configuration

### Host Group with Protocol Inspection

Configure protocol inspection for host group VirtualServers:

```yaml
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: hostgroup-secure-app
  namespace: default
spec:
  hostGroup: "secure-apps"
  virtualServerAddress: "10.192.75.114"
  profiles:
    profileProtocolInspection: "/Common/hostgroup_security_profile"
  pools:
  - path: /app1
    service: app1-service
    servicePort: 8080
    hostRewrite: "app1.internal.com"
  - path: /app2
    service: https-service
    servicePort: 443
    hostRewrite: "app2.internal.com"
```

### Multiple Virtual IPs with Protocol Inspection

Configure protocol inspection across multiple virtual server addresses:

```yaml
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: multi-vip-secure-app
  namespace: default
spec:
  host: multi.example.com
  virtualServerAddress: "10.192.75.115"
  additionalVirtualServerAddresses:
  - "10.192.75.116"
  - "10.192.75.117"
  profiles:
    profileProtocolInspection: "/Common/multi_vip_security_profile"
  pools:
  - path: /
    service: web-service
    servicePort: 80
```

## BIG-IP Prerequisites

1. **Create Protocol Inspection Profile** on BIG-IP:
   ```bash
   tmsh create ltm profile protocol-security protocol_inspection_profile
   ```

2. **Configure profile settings** (optional):
   ```bash
   tmsh modify ltm profile protocol-security protocol_inspection_profile {
       services add { http https }
       inspect-profile enabled
   }
   ```

3. **Ensure profile accessibility** from the CIS partition

## AS3 Declaration Output

CIS generates AS3 declarations with protocol inspection profiles for VirtualServer:

```json
{
  "class": "AS3",
  "declaration": {
    "Sample_app": {
      "my_virtualserver_80": {
        "class": "Service_HTTP",
        "profileProtocolInspection": {
          "use": "/Common/protocol_inspection_profile"
        },
        "virtualAddresses": ["10.192.75.108"],
        "virtualPort": 80
      }
    }
  }
}
```

## Validation

### Verify VirtualServer Configuration

1. **Check CIS processes the VirtualServer**:
   ```bash
   kubectl logs -n kube-system <cis-pod-name> | grep -i "my-virtualserver"
   ```

2. **Verify AS3 declaration**:
   ```bash
   curl -k -u admin:password https://<bigip>/mgmt/shared/appsvcs/declare
   ```

3. **Check BIG-IP virtual server**:
   ```bash
   tmsh show ltm virtual <virtual-server-name> profiles
   ```

4. **Test protocol inspection functionality**:
   ```bash
   curl -H "Host: example.com" http://10.192.75.108/
   ```

## Troubleshooting

- **Profile not applied**: Check that the protocol inspection profile exists on BIG-IP
- **AS3 deployment fails**: Verify profile path format (e.g., `/Common/profile_name`)
- **Virtual server not created**: Check CIS logs for VirtualServer processing errors
- **Profile conflicts**: Ensure protocol inspection profile is compatible with other configured profiles
- **Host resolution issues**: Verify DNS or host header configuration

## Notes

- Protocol inspection profiles must exist on BIG-IP before referencing in VirtualServer
- Profile names must include the full path (e.g., `/Common/profile_name`)
- VirtualServer `profileProtocolInspection` settings override Policy settings when both are configured
- Empty `profileProtocolInspection` values disable protocol inspection for that VirtualServer
- Protocol inspection works with both HTTP and HTTPS virtual servers
- Changes to protocol inspection profiles require AS3 declaration updates

## Related Examples

- See [virtual-server-with-protocol-inspection.yaml](./virtual-server-with-protocol-inspection.yaml) for a complete example
- See [Profiles/](./Profiles/) for other profile configuration examples