# Load Balancer Class Support

Kubernetes 1.24 and later have introduced the standard .spec.loadBalancerClass field in the service spec to be able to distinguish between the types of load balancing services available to the cluster, so that you can specify which load balancing class you would like to use. [See here](https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class)

This document describes the CIS support for Load Balancer Class.

## Overview

By default, CIS will process all the services that do not have the loadBalancerClass field set in the service spec. CIS will not process the services that have the loadBalancerClass field set in the service spec.
If you have configured the loadBalancerClass field in the service for TS/IngressLink/SvcLB, then configure the CIS deployment parameter `load-balancer-class` to the same value, Otherwise CIS will not process the service with loadBalancerClass field configured in the service for TS/VS/IngressLink/SvcLB.

Note:
* Load Balancer Class is supported for all the Custom Resources (VirtualServer, TransportServer and IngressLink) and loadBalancer service by default and can not be disabled at all. You need to either remove the loadBalancerClass field from the service or configure the CIS deployment parameter `load-balancer-class` to the same value as the loadBalancerClass field in the service.

## CIS Deployment parameters for Load Balancer Class

CIS supports two deployment parameters for Load Balancer Class.

| Deployment Parameter            | Type    | Required | Default Value | Description                                                                                                                                                                                                                                                                | Allowed Value |
|---------------------------------|---------|----------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| load-balancer-class             | String  | Optional | ""            | CIS considers services only that matches the specified class. CIS will ignore services that have this field set and does not match with the provided load-balancer-class                                                                                                   |               | 
| manage-load-balancer-class-only | Boolean | Optional | false         | If set to true, CIS processes all load balancer services with loadBalancerClass only. <br> If set to false, CIS process all the load balancer service without loadBalancerClass and service that have the loadBalancerClass specified by the load-balancer-class parameter | true, false   |
