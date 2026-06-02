# Protocol Inspection Profile in Policy CRD

This document describes how to configure Protocol Inspection Profiles using the Policy Custom Resource Definition (CRD) in F5 Container Ingress Services (CIS).

## Overview

Protocol Inspection Profiles enable deep packet inspection capabilities on F5 BIG-IP systems to analyze and control network traffic based on application protocols. The Policy CRD allows you to create reusable protocol inspection configurations that can be applied to multiple VirtualServer and TransportServer resources.

## Configuration

### Basic Policy with Protocol Inspection

Create a reusable protocol inspection configuration:

```yaml
apiVersion: cis.f5.com/v1
kind: Policy
metadata:
  name: protocol-inspection-policy
  namespace: default
spec:
  profiles:
    profileProtocolInspection: "/Common/shared_protocol_inspection"
```

### Apply Policy to VirtualServer

Reference the policy in a VirtualServer:

```yaml
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: web-app-with-policy
  namespace: default
spec:
  host: example.com
  virtualServerAddress: "10.192.75.108"
  policyName: protocol-inspection-policy
  pools:
  - path: /
    service: web-service
    servicePort: 80
```

### Apply Policy to TransportServer

Reference the policy in a TransportServer:

```yaml
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: tcp-service-with-policy
  namespace: default
spec:
  virtualServerAddress: "10.192.75.109"
  virtualServerPort: 8080
  type: tcp
  mode: standard
  policyName: protocol-inspection-policy
  pool:
    service: tcp-service
    servicePort: 8080
```

## Priority Behavior

When both Policy and resource-specific profiles are configured, **resource-specific profiles take precedence**:

```yaml
# Policy defines protocol inspection
apiVersion: cis.f5.com/v1
kind: Policy
metadata:
  name: base-policy
spec:
  profiles:
    profileProtocolInspection: "/Common/policy_profile"

---
# VirtualServer overrides policy profile
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: override-example
spec:
  policyName: base-policy
  profiles:
    profileProtocolInspection: "/Common/vs_specific_profile"  # This takes precedence
```

## Complete Example

Policy with multiple profile configurations:

```yaml
apiVersion: cis.f5.com/v1
kind: Policy
metadata:
  name: security-policy
  namespace: production
spec:
  profiles:
    profileProtocolInspection: "/Common/production_security_profile"
    tcp:
      client: "/Common/tcp-wan-optimized"
      server: "/Common/tcp-lan-optimized"
  l7Policies:
    waf: "/Common/asm_policy"
  ltmPolicies:
  - "/Common/header_rewrite_policy"

---
apiVersion: cis.f5.com/v1
kind: VirtualServer
metadata:
  name: secure-app
  namespace: production
spec:
  host: secure.example.com
  virtualServerAddress: "10.192.75.110"
  policyName: security-policy
  pools:
  - path: /api
    service: api-service
    servicePort: 8080
  - path: /
    service: web-service
    servicePort: 80
```

## BIG-IP Prerequisites

1. **Create Protocol Inspection Profile** on BIG-IP:
   ```bash
   tmsh create ltm profile protocol-security shared_protocol_inspection
   ```

2. **Ensure profile accessibility** from the CIS partition (usually `/Common/`)

## Validation

### Check Policy Application

1. **Verify CIS processes the policy**:
   ```bash
   kubectl logs -n kube-system <cis-pod-name> | grep -i "protocol-inspection-policy"
   ```

2. **Check AS3 declaration includes the profile**:
   ```bash
   curl -k -u admin:password https://<bigip>/mgmt/shared/appsvcs/declare | jq '.declaration'
   ```

3. **Verify BIG-IP virtual server configuration**:
   ```bash
   tmsh show ltm virtual <virtual-server-name> profiles
   ```

## Troubleshooting

- **Policy not applied**: Check that `policyName` matches the Policy resource name
- **Profile not found**: Ensure the protocol inspection profile exists on BIG-IP
- **AS3 deployment fails**: Verify profile path format (e.g., `/Common/profile_name`)
- **Configuration ignored**: Check CIS logs for policy processing errors

## Notes

- Policy protocol inspection profiles apply to both VirtualServer and TransportServer resources
- Profile names must include the full path (e.g., `/Common/profile_name`)
- Resource-specific `profileProtocolInspection` settings override Policy settings
- Empty profile values in Policy disable protocol inspection unless overridden by the resource
- Changes to Policy profiles require AS3 declaration updates