# Protocol Inspection Profile in TransportServer CRD

This document describes how to configure Protocol Inspection Profiles directly in TransportServer Custom Resource Definition (CRD) for F5 Container Ingress Services (CIS).

## Overview

Protocol Inspection Profiles enable deep packet inspection capabilities on F5 BIG-IP systems to analyze and control network traffic based on application protocols. TransportServer CRD allows you to configure protocol inspection profiles directly for TCP/UDP/SCTP virtual servers.

## Configuration

### Basic TCP TransportServer with Protocol Inspection

Configure protocol inspection directly in TransportServer specs:

```yaml
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: tcp-server-with-inspection
  namespace: default
spec:
  virtualServerAddress: "10.192.75.108"
  virtualServerPort: 8080
  type: tcp
  mode: standard
  profiles:
    profileProtocolInspection: "/Common/tcp_protocol_inspection"
  pool:
    service: tcp-service
    servicePort: 8080
```

### TransportServer with Multiple Profiles

Combine protocol inspection with TCP profiles:

```yaml
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: secure-tcp-server
  namespace: default
spec:
  virtualServerAddress: "10.192.75.109"
  virtualServerPort: 9090
  type: tcp
  mode: standard
  profiles:
    profileProtocolInspection: "/Common/tcp_security_profile"
    tcp:
      client: "/Common/tcp-mobile-optimized"
      server: "/Common/tcp-lan-optimized"
  pool:
    service: database-service
    servicePort: 9090
```

### UDP TransportServer with Protocol Inspection

Configure protocol inspection for UDP services:

```yaml
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: udp-server-with-inspection
  namespace: default
spec:
  virtualServerAddress: "10.192.75.110"
  virtualServerPort: 5353
  type: udp
  mode: standard
  profiles:
    profileProtocolInspection: "/Common/udp_dns_inspection"
  pool:
    service: dns-service
    servicePort: 53
```

### Performance Mode with Protocol Inspection

Configure protocol inspection with performance mode:

```yaml
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: high-performance-tcp
  namespace: default
spec:
  virtualServerAddress: "10.192.75.111"
  virtualServerPort: 3306
  type: tcp
  mode: performance
  profiles:
    profileProtocolInspection: "/Common/mysql_protocol_inspection"
  pool:
    service: mysql-service
    servicePort: 3306
```

## Policy Integration

### TransportServer with Policy Override

When using policies, TransportServer profiles take precedence:

```yaml
apiVersion: cis.f5.com/v1
kind: Policy
metadata:
  name: base-tcp-policy
  namespace: default
spec:
  profiles:
    profileProtocolInspection: "/Common/default_tcp_inspection"

---
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: custom-tcp-server
  namespace: default
spec:
  virtualServerAddress: "10.192.75.112"
  virtualServerPort: 8443
  type: tcp
  mode: standard
  policyName: base-tcp-policy
  profiles:
    profileProtocolInspection: "/Common/custom_tcp_inspection"  # Overrides policy
  pool:
    service: secure-tcp-service
    servicePort: 8443
```

## Complete Production Example

Real-world TransportServer with comprehensive configuration:

```yaml
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: production-tcp-service
  namespace: production
spec:
  virtualServerAddress: "10.192.75.113"
  virtualServerPort: 1521
  type: tcp
  mode: standard
  profiles:
    profileProtocolInspection: "/Common/oracle_protocol_inspection"
    tcp:
      client: "/Common/tcp-wan-optimized"
      server: "/Common/tcp-lan-optimized"
  connectionMirroring: enabled
  allowVlans:
  - "/Common/internal-vlan"
  - "/Common/dmz-vlan"
  pool:
    service: oracle-database
    servicePort: 1521
    serviceNamespace: database
    monitor:
      type: tcp
      interval: 10
      timeout: 31
    loadBalancingMethod: least-connections-member
```

## Advanced Configuration

### SCTP TransportServer with Protocol Inspection

Configure protocol inspection for SCTP services:

```yaml
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: sctp-server-with-inspection
  namespace: telecom
spec:
  virtualServerAddress: "10.192.75.114"
  virtualServerPort: 2905
  type: sctp
  mode: standard
  profiles:
    profileProtocolInspection: "/Common/diameter_protocol_inspection"
  pool:
    service: diameter-service
    servicePort: 3868
    monitor:
      type: tcp
      interval: 5
      timeout: 16
```

### Multiple Pools with Protocol Inspection

TransportServer with alternate backends:

```yaml
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: multi-backend-tcp
  namespace: default
spec:
  virtualServerAddress: "10.192.75.115"
  virtualServerPort: 6379
  type: tcp
  mode: standard
  profiles:
    profileProtocolInspection: "/Common/redis_protocol_inspection"
  pool:
    service: redis-primary
    servicePort: 6379
    weight: 100
    alternateBackends:
    - service: redis-replica
      servicePort: 6379
      weight: 50
```

### TransportServer with Custom Health Monitoring

Combine protocol inspection with custom health checks:

```yaml
apiVersion: cis.f5.com/v1
kind: TransportServer
metadata:
  name: monitored-tcp-server
  namespace: default
spec:
  virtualServerAddress: "10.192.75.116"
  virtualServerPort: 5432
  type: tcp
  mode: standard
  profiles:
    profileProtocolInspection: "/Common/postgresql_inspection"
  pool:
    service: postgresql-service
    servicePort: 5432
    monitor:
      type: tcp
      send: "SELECT 1"
      recv: "1"
      interval: 30
      timeout: 10
```

## BIG-IP Prerequisites

1. **Create Protocol Inspection Profile** on BIG-IP:
   ```bash
   tmsh create ltm profile protocol-security tcp_protocol_inspection
   ```

2. **Configure profile for specific protocols**:
   ```bash
   tmsh modify ltm profile protocol-security tcp_protocol_inspection {
       services add { tcp }
       inspect-profile enabled
   }
   ```

3. **Ensure profile accessibility** from the CIS partition

## AS3 Declaration Output

CIS generates AS3 declarations with protocol inspection profiles for TransportServer:

```json
{
  "class": "AS3",
  "declaration": {
    "Sample_app": {
      "tcp_server_with_inspection_8080": {
        "class": "Service_TCP",
        "profileProtocolInspection": {
          "use": "/Common/tcp_protocol_inspection"
        },
        "virtualAddresses": ["10.192.75.108"],
        "virtualPort": 8080
      }
    }
  }
}
```

## Validation

### Verify TransportServer Configuration

1. **Check CIS processes the TransportServer**:
   ```bash
   kubectl logs -n kube-system <cis-pod-name> | grep -i "tcp-server-with-inspection"
   ```

2. **Verify AS3 declaration**:
   ```bash
   curl -k -u admin:password https://<bigip>/mgmt/shared/appsvcs/declare
   ```

3. **Check BIG-IP virtual server**:
   ```bash
   tmsh show ltm virtual <transport-server-name> profiles
   ```

4. **Test TCP connection**:
   ```bash
   telnet 10.192.75.108 8080
   ```

5. **Monitor protocol inspection logs**:
   ```bash
   tmsh show ltm profile protocol-security tcp_protocol_inspection stats
   ```

## Transport Server Types and Protocol Inspection

### TCP Services
- Database servers (MySQL, PostgreSQL, Oracle)
- Message brokers (Redis, RabbitMQ)
- Custom TCP applications

### UDP Services
- DNS servers
- DHCP servers
- Game servers
- Streaming applications

### SCTP Services
- Telecom applications (Diameter)
- Signaling protocols
- Network control protocols

## Troubleshooting

- **Profile not applied**: Check that the protocol inspection profile exists on BIG-IP
- **AS3 deployment fails**: Verify profile path format (e.g., `/Common/profile_name`)
- **TransportServer not created**: Check CIS logs for TransportServer processing errors
- **Connection issues**: Verify virtual server address and port accessibility
- **Profile conflicts**: Ensure protocol inspection profile is compatible with transport type (TCP/UDP/SCTP)
- **Performance impact**: Monitor BIG-IP performance when using protocol inspection with high-throughput services

## Notes

- Protocol inspection profiles must exist on BIG-IP before referencing in TransportServer
- Profile names must include the full path (e.g., `/Common/profile_name`)
- TransportServer `profileProtocolInspection` settings override Policy settings when both are configured
- Empty `profileProtocolInspection` values disable protocol inspection for that TransportServer
- Protocol inspection works with TCP, UDP, and SCTP transport types
- Performance mode may have limitations with certain protocol inspection features
- Changes to protocol inspection profiles require AS3 declaration updates

## Related Examples

- See [transport-server-with-protocol-inspection.yaml](./transport-server-with-protocol-inspection.yaml) for a complete TCP example
- See [simple-transport-server-with-protocol-inspection.yaml](./simple-transport-server-with-protocol-inspection.yaml) for a basic example
- See [transport-server-with-policy-protocol-inspection.yaml](./transport-server-with-policy-protocol-inspection.yaml) for policy integration