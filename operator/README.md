## F5 BIG-IP Controller Operator

An Operator is a method of packaging, deploying and managing a Kubernetes application. A Kubernetes application is an application that is both deployed on Kubernetes and managed using the Kubernetes APIs and kubectl/oc tooling. You can think of Operators as the runtime that manages this type of application on Kubernetes. 

Conceptually, an Operator takes human operational knowledge and encodes it into software that is more easily packaged and shared with consumers. 

F5 BIG-IP Controller Operator is a Service Operator which installs F5 BIG-IP Controller (Container Ingress Services) on Kubernetes and OpenShift platforms and respective supported versions.

F5 Helm Charts - https://github.com/F5Networks/charts

Sample Configuration for kind `F5BigIpCtlr`:

```
apiVersion: cis.f5.com/v1
kind: F5BigIpCtlr
metadata:
  name: f5-server
  namespace: openshift-operators
spec:
  args:
    log_as3_response: true
    manage_routes: true
    agent: as3
    log_level: DEBUG_OR_INFO
    route_vserver_addr: IP_ADDRESS
    bigip_partition: BIGIP_PARTITION
    openshift_sdn_name: /BIGIP_PARTITION/SDN_NAME
    bigip_url: BIGIP_IP_ADDRESS
    insecure: true
    pool-member-type: CLUSTER_OR_NODEPORT_OR_LOADBALANCER
  bigip_login_secret: BIG-IP_K8S_SECRET
  image:
    pullPolicy: Always
    repo: k8s-bigip-ctlr
    user: f5networks
  namespace: kube-system
  rbac:
    create: true
  resources: {}
  serviceAccount:
    create: true
  version: latest

```
