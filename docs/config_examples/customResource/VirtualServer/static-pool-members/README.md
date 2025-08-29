
# Static Pool Members Support in VirtualServer

## 1. Feature Overview

Static pool members in a VirtualServer allow you to explicitly define backend servers (by IP address and port) that will receive traffic for a given VirtualServer. 
- Under the `pools` field for each pool
- In the `alternateBackends` section
- In the `defaultPool` section (`defaultPool.staticPoolMembers`)
- In a referenced Policy resource’s `defaultPool` (`Policy.spec.defaultPool.staticPoolMembers`)

**Note**:
- This feature is only supported with Virtual Server, Not supported for other resources
- Not supported in multiCluster mode

---

## 2. VirtualServer Normal Pool

A normal pool in a VirtualServer is specified under the `pools` field. Each pool can contain a list of static pool members, which are the backend servers for that pool.

**Example:**
```yaml
pools:
  - name: app-pool
    staticPoolMembers:
      - address: 192.168.1.10
        port: 8080
      - address: 192.168.1.11
        port: 8080
```

---

## 3. Alternate Backend

**Example:**
```yaml
alternateBackends:
  - name: backup-pool
    staticPoolMembers:
      - address: 192.168.1.20
        port: 8080
```

---

## 4. Default Pool

**Example:**
```yaml
defaultPool:
  staticPoolMembers:
    - address: 192.168.1.30
      port: 8080
```

---

## 5. Policy Default

A Policy resource can define a `defaultPool` that applies to all VirtualServers referencing that policy. This centralizes backend configuration and simplifies management across multiple VirtualServers.

**Example:**
```yaml
apiVersion: cis.f5.com/v1
kind: Policy
metadata:
  name: global-policy
spec:
  defaultPool:
    staticPoolMembers:
      - address: 192.168.1.40
        port: 8080
```

---

## 6. Precedence: VirtualServer vs Policy Default Pool Static Pool Members 

```markdown
When both a VirtualServer and its referenced Policy define `defaultPool.staticPoolMembers`, the VirtualServer's `defaultPool.staticPoolMembers` take precedence. If the VirtualServer does not define `defaultPool.staticPoolMembers`, the controller will use the Policy's `defaultPool.staticPoolMembers` instead. This ensures that VirtualServer-specific static pool members override global policy defaults when both are present.
```

**Precedence Logic:**
- If `VirtualServer.defaultPool.staticPoolMembers` is defined, it is used.
- If not, and `Policy.defaultPool.staticPoolMembers` is defined, the policy's staticPoolMembers is used.

---
