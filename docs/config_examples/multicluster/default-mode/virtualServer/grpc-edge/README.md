# Secure Virtual Server with TLS Profile for gRPC with Edge Termination

This section demonstrates the deployment of a Secure Virtual Server with gRPC support and edge termination using BIG-IP TLS profiles.

## Overview

gRPC requires HTTP/2 (h2c over clear‑text) for non-SSL pool backends. To configure h2c on a BIG-IP virtual server, the backend server must be configured to support the direct method for h2c negotiation.

## BIG-IP Configuration Requirements

### Server-side BIG-IP configuration requires:
- An HTTP/2 Profile (Server) with the "Activation Modes" parameter set to "Always"
![HTTP/2 Profile (Server)](./http2-server-profile.png "HTTP/2 Profile (Server)")

### Client-side BIG-IP configuration requires:
- Client SSL Profile (Client) with the "SSL Renegotiation" parameter set to "disabled" 
- HTTP/2 Profile (Client) with appropriate settings for client-side HTTP/2 support

## Configuration Files

### grpc-vs.yml

By deploying this YAML file in your cluster, CIS will create a Virtual Server on BIG-IP with the specified VIP. It will load balance gRPC traffic with proper HTTP/2 support and edge termination.

### edge-tls.yml

By deploying this YAML file in your cluster, CIS will attach the appropriate TLS profile for edge termination to the Virtual Server, enabling secure gRPC communication.

## Creating Kubernetes Secrets with Certificates for BIG-IP

To create the necessary TLS secrets for your gRPC service:

```shell
kubectl create secret tls <secret-name> --cert=<path/to/certificate.crt> --key=<path/to/private.key> -n <namespace>
```

## Important Notes

- Ensure your gRPC backend services support HTTP/2 (h2c) protocol
- The BIG-IP must have the appropriate HTTP/2 profiles configured as described above
- Edge termination means SSL/TLS is terminated at the BIG-IP, and traffic to backend pods is unencrypted
- Backend services should be configured to handle HTTP/2 clear-text connections
