# Leader Election Integration Design Document

## Overview

This document describes the design and implementation of leader election mechanism integrated into the F5 Container Ingress Services (CIS) controller to enable high availability and prevent conflicts when multiple CIS instances are deployed against the same BIG-IP device.

## Background

### Problem Statement

When multiple CIS instances are deployed in a high-availability setup, they may simultaneously attempt to configure the same BIG-IP device, leading to:
- Configuration conflicts and race conditions
- Duplicate or conflicting virtual servers and pools
- Inconsistent state between CIS instances
- Resource contention on BIG-IP
- Flow timeouts and dropped gRPC requests due to sweeper idle timeouts

### Requirements

1. **Single Active Instance**: Only one CIS instance should actively configure BIG-IP at any given time
2. **High Availability**: Automatic failover when the active instance becomes unavailable
3. **BIG-IP Integration**: Use BIG-IP's internal data groups for coordination to avoid external dependencies
4. **Secure Communication**: Leverage existing tokenmanager and bigiphandler for secure BIG-IP communication
5. **Minimal Disruption**: Seamless integration without breaking existing functionality
6. **Testability**: Comprehensive test coverage using Ginkgo framework

## Architecture

### Components Overview

The leader election system consists of three main components:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Controller    │    │  RequestHandler  │    │ LeaderElector   │
│                 │────│                  │────│                 │
│ - Manages LE    │    │ - Filters reqs   │    │ - Heartbeat     │
│ - Lifecycle     │    │ - Leader checks  │    │ - Monitor       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     BIG-IP DataGroup    │
                    │   "leader_election"     │
                    │                         │
                    │ Record: "leader"        │
                    │ Data: "candidate_id ts" │
                    └─────────────────────────┘
```

### Leader Election Package

#### Core Components

1. **LeaderElector**: Main orchestrator for leader election logic
2. **LeaderElectorConfig**: Configuration structure for initialization
3. **TokenManager Integration**: Secure authentication with BIG-IP
4. **BigIPHandler Integration**: Manages BIG-IP API communications

#### Key Interfaces and Types

```
type LeaderElectorConfig struct {
    CandidateID  string
    BigipHost    string
    Username     string
    Password     string
    TrustedCerts string
    SslInsecure  bool
    UserAgent    string
    Teem         bool
}

type LeaderElector struct {
    config       LeaderElectorConfig
    tokenManager tokenmanager.TokenManagerInterface
    bigipHandler *bigiphandler.BigIPHandler
    stopCh       chan struct{}
    mu           sync.Mutex
    isLeader     bool
    httpClient   *http.Client
}
```

## Implementation Details

### Leader Election Algorithm

The implementation uses a **lease-based leader election** algorithm with the following characteristics:

1. **Heartbeat Mechanism**: Leaders periodically update their lease with a timestamp
2. **Lease Expiry**: If a leader fails to update within the timeout period, it's considered dead
3. **Leadership Acquisition**: Any candidate can become leader if no active leader exists
4. **Graceful Handover**: Leaders voluntarily step down when they detect another active leader

#### State Transitions

```
┌─────────────┐    No Leader/    ┌─────────────┐
│  Candidate  │    Lease Expired │   Leader    │
│             │─────────────────→│             │
│ (Monitoring)│                  │(Heartbeat)  │
│             │←─────────────────│             │
└─────────────┘   Another Leader └─────────────┘
                  Detected
```

### BIG-IP Data Group Structure

The leader election uses BIG-IP internal data groups for coordination:

- **Data Group Name**: `leader_election`
- **Type**: `string`
- **Record Structure**:
  - **Name**: `leader`
  - **Data**: `{candidate_id} {unix_timestamp}`

Example:
```json
{
  "name": "leader_election",
  "type": "string",
  "records": [
    {
      "name": "leader",
      "data": "cis-instance-1 1642680123"
    }
  ]
}
```

### Timing Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `heartbeatInterval` | 10 seconds | Frequency of leader heartbeat updates |
| `heartbeatTimeout` | 50 seconds | Maximum time before considering leader dead |
| `tokenRefreshInterval` | 15 minutes | BIG-IP token refresh frequency |

### Controller Integration

#### RequestHandler Modifications

The `RequestHandler` has been enhanced to include leader election awareness:

```
type RequestHandler struct {
    // ...existing fields...
    leaderElector *leaderelection.LeaderElector
}

func (reqHandler *RequestHandler) requestHandler() {
    for rsConfig := range reqHandler.reqChan {
        // Check if leader election is enabled and if this instance is the leader
        if reqHandler.hasLeaderElection() && !reqHandler.isLeader() {
            log.Debugf("Leader election enabled but this instance is not the leader, skipping request processing")
            continue
        }
        
        // ...existing request processing logic...
    }
}
```

#### Controller Lifecycle

The `Controller` struct has been extended to manage the leader election lifecycle:

```
type Controller struct {
    // ...existing fields...
    leaderElector *leaderelection.LeaderElector
}
```

## Security Considerations

### Authentication and Authorization

1. **Token-based Authentication**: Uses existing `tokenmanager` for secure BIG-IP authentication
2. **TLS/SSL Configuration**: Supports custom trusted certificates and SSL verification settings
3. **Credential Management**: Reuses existing credential management patterns from CIS

### Access Control

1. **BIG-IP Permissions**: Requires permissions to create/modify internal data groups
2. **Network Security**: All communications use HTTPS with configurable certificate validation
3. **Token Lifecycle**: Automatic token refresh prevents expired credential issues

## Testing Strategy

### Unit Tests (Ginkgo Framework)

The test suite covers the following scenarios:

#### Basic Leader Election
- Single candidate becoming leader
- Multiple candidates competing for leadership
- Leader stepping down when another leader is detected

#### Heartbeat Management
- Periodic heartbeat updates when leader
- No heartbeat updates when not leader
- Leader stepping down on heartbeat failure

#### Data Group Operations
- Creating new data groups
- Updating existing data groups
- Reading leader information
- Handling missing/malformed data

#### Error Handling
- Network failures
- BIG-IP API errors
- Token refresh failures
- Malformed data handling

#### Integration Testing
- TokenManager integration
- BigIPHandler integration
- Mock BIG-IP client behavior

### Test Structure

```
var _ = Describe("LeaderElection", func() {
    Describe("Leader Election Basics", func() {
        It("should become leader if no leader is present")
        It("should not become leader if another leader is active")
        It("should step down when another leader takes over")
    })
    
    Describe("Heartbeat Management", func() {
        It("should send heartbeats when leader")
        It("should not send heartbeats when not leader")
        It("should step down if heartbeat fails")
    })
    
    Describe("Data Group Operations", func() {
        It("should create datagroup if it doesn't exist")
        It("should update existing datagroup")
        It("should read leader information correctly")
    })
})
```

## Configuration

### Environment Variables

Leader election can be configured through the following parameters:

```yaml
leaderElection:
  enabled: true
  candidateId: "cis-instance-1"
  bigipHost: "192.168.1.100"
  heartbeatInterval: "10s"
  heartbeatTimeout: "50s"
```

### Integration with Existing Configuration

The leader election configuration integrates seamlessly with existing CIS configuration patterns, reusing:
- BIG-IP connection parameters
- TLS/SSL settings
- Authentication credentials
- Logging configuration

## Deployment Considerations

### High Availability Setup

1. **Multiple CIS Instances**: Deploy multiple CIS instances with identical configuration
2. **Unique Candidate IDs**: Each instance must have a unique `candidateId`
3. **Shared BIG-IP Access**: All instances must have access to the same BIG-IP device
4. **Network Connectivity**: Reliable network connectivity between CIS instances and BIG-IP

### Monitoring and Observability

#### Logging

The leader election system provides comprehensive logging:

```
[Leader Election] Started leader election for candidate cis-instance-1
[Leader Election] No active leader found. Candidate cis-instance-1 becoming leader
[Leader Election] Leader cis-instance-1 wrote heartbeat
[Leader Election] Candidate cis-instance-1 stepping down. Current leader is cis-instance-2
```

#### Metrics

Key metrics for monitoring:
- Leader election status
- Heartbeat success/failure rates
- Leadership transition frequency
- BIG-IP API call success rates

## Migration and Compatibility

### Backward Compatibility

The leader election integration maintains full backward compatibility:
- **Default Behavior**: When leader election is disabled, CIS behaves exactly as before
- **Configuration**: Existing configurations continue to work without modification
- **API Compatibility**: No changes to existing CIS APIs or resource definitions

### Migration Path

1. **Phase 1**: Deploy updated CIS version with leader election disabled
2. **Phase 2**: Enable leader election on one instance for testing
3. **Phase 3**: Gradually enable leader election on all instances
4. **Phase 4**: Monitor and validate leader election behavior

## Performance Impact

### Resource Usage

- **Memory**: Minimal additional memory usage (~1-2 MB per instance)
- **CPU**: Low CPU overhead for heartbeat and monitoring operations
- **Network**: Periodic API calls to BIG-IP (every 10 seconds when leader)

### Latency Considerations

- **Request Processing**: No additional latency for request processing when leader
- **Failover Time**: Maximum failover time is `heartbeatTimeout` (50 seconds)
- **Leadership Acquisition**: Near-instantaneous when no active leader exists

## Future Enhancements

### Planned Improvements

1. **Configurable Timing**: Make heartbeat intervals and timeouts configurable
2. **Health Checks**: Integrate with existing health check mechanisms
3. **Metrics Export**: Export leader election metrics to Prometheus
4. **Event Generation**: Generate Kubernetes events for leadership changes
5. **Multi-BIG-IP Support**: Extend to support multiple BIG-IP devices with separate elections

### Extension Points

The current design provides extension points for:
- Custom election algorithms
- Alternative storage backends
- Enhanced monitoring and alerting
- Integration with external coordination services

## Conclusion

The leader election integration provides a robust, secure, and scalable solution for managing multiple CIS instances in high-availability deployments. By leveraging BIG-IP's internal data groups and existing CIS infrastructure, the implementation minimizes external dependencies while providing strong consistency guarantees.

The design prioritizes:
- **Reliability**: Robust failover and recovery mechanisms
- **Security**: Secure authentication and communication
- **Performance**: Minimal overhead and fast failover times
- **Maintainability**: Clean integration with existing codebase
- **Testability**: Comprehensive test coverage and mock support

This implementation addresses the core requirements while maintaining backward compatibility and providing a foundation for future enhancements.
