# VirtualServer
This resource configures F5 BIG-IP to load balance HTTP and HTTPS traffic to a set of Kubernetes services. The VirtualServer resource exposes HTTP and HTTPS traffic on defined virtual addresses.

## Components
### VirtualServer Components

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| host | String | Optional | N/A | Virtual Host on which the virtual server is created |
| virtualServerAddress | String | Optional | N/A | IP address on which the virtual server is created |
| virtualServerName | String | Optional | N/A | Custom name for the Virtual Server |
| tlsProfileName | String | Optional | N/A | TLS profile name for TLS termination |
| httpTraffic | String | Optional | allow | Specify whether to allow HTTP traffic: `allow`, `none`, `redirect` |
| snat | String | Optional | auto | Reference to SNAT pool on BIG-IP. Allowed values: `auto` (default), `none`, or SNAT pool name |
| pools | Array | Required | N/A | List of pools for the virtual server |
| profiles | Object | Optional | N/A | Various BIG-IP profiles for the virtual server |

### Profile Components

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| tcp | Object | Optional | N/A | TCP Client & Server Profiles |
| http | String | Optional | N/A | Pathname of existing BIG-IP HTTP profile |
| http2 | Object | Optional | N/A | HTTP2 Client & Server Profiles |
| persistenceProfile | String | Optional | cookie | Pathname of existing BIG-IP persistence profile |
| profileProtocolInspection | String | Optional | N/A | Reference to existing BIG-IP Protocol Inspection profile |

### TCP Profile Components

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| client | String | Optional | N/A | Pathname of existing BIG-IP TCP client profile |
| server | String | Optional | N/A | Pathname of existing BIG-IP TCP server profile |

### HTTP2 Profile Components  

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| client | String | Optional | N/A | Pathname of existing BIG-IP HTTP2 client profile |
| server | String | Optional | N/A | Pathname of existing BIG-IP HTTP2 server profile |

### Pool Components

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| path | String | Optional | / | URL path for the pool |
| service | String | Required | N/A | Kubernetes service name |
| servicePort | Integer | Required | N/A | Kubernetes service port |
| serviceNamespace | String | Optional | Current namespace | Kubernetes service namespace |

## Examples

The following examples demonstrate how to use the VirtualServer resource:

- [Basic Virtual Server](virtual-server-with-protocol-inspection.yaml)
- [Virtual Server with Profiles](virtual-server-with-profiles.yaml)

## Notes

- The VirtualServer resource requires at least one pool to be defined
- Protocol Inspection profiles help analyze and secure application traffic
- Multiple profiles can be configured to customize traffic handling