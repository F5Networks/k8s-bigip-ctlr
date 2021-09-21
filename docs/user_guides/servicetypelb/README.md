# Service Type LoadBalancer

A service of type LoadBalancer is the simplest and the fastest way to expose a service inside a Kubernetes cluster to the external world. All you need to-do is specify the service type as type=LoadBalancer in the service definition.

Services of type LoadBalancer are natively supported in Kubernetes deployments. When you create a service of type LoadBalancer, Kubernetes spins up a service in integration with F5 IPAM Controller which allocates an IP address from the ip-range specified by the ipamlabel. Using CIS with services configured for type LoadBalancer, BIG-IP can load balance the incoming traffic to the Kubernetes cluster without having to create any ingress resource. CIS will manage the public IP addresses for the application using the F5 IPAM Controller. This cloud like simplification of load balancer resources could significantly reduce your operational expenses.

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/servicetypelb/diagram/2021-04-27_10-11-10.png)

Demo on YouTube [video](https://www.youtube.com/watch?v=IEAzvkRjWAE)

Looking at the diagram and Service of type LoadBalancer, the following events occur:

1. CIS will update the service whenever the loadBalancer IP in the service is empty.
2. The IPAM controller assigns an IP address for the loadBalancer: ingress: object from the ip-range based on the ipamlabel specified but the annotation
3. Once the object is updated with the IP address, CIS automatically configures BIG-IP with the External IP address as shown below

#### Example of Service type LoadBalancer shown in the diagram

```
apiVersion: v1
kind: Service
metadata:
  annotations:
    cis.f5.com/ipamLabel: Test
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Service","metadata":{"annotations":{"cis.f5.com/ipamLabel":"Test"},"labels":{"app":"f5-demo"},"name":"f5-demo","namespace":"default"},"spec":{"ports":[{"name":"f5-demo","port":80,"protocol":"TCP","targetPort":80}],"selector":{"app":"f5-demo"},"sessionAffinity":"None","type":"LoadBalancer"},"status":{"loadBalancer":null}}
  creationTimestamp: "2021-04-19T18:05:23Z"
  labels:
    app: f5-demo
  name: f5-demo
  namespace: default
  resourceVersion: "52258409"
  selfLink: /api/v1/namespaces/default/services/f5-demo
  uid: d8336cc3-8611-48d9-bcfc-c3521c45eef1
spec:
  clusterIP: 10.111.131.138
  externalTrafficPolicy: Cluster
  ports:
  - name: f5-demo
    nodePort: 31970
    port: 80
    protocol: TCP
    targetPort: 80
  selector:
    app: f5-demo
  sessionAffinity: None
  type: LoadBalancer
status:
  loadBalancer:
    ingress:
    - ip: 10.192.75.113

```

## Configuring Service Type LoadBalancer

## Prerequisites

* Recommend AS3 version 3.26 [repo](https://github.com/F5Networks/f5-appsvcs-extension/releases/tag/v3.26.0)
* CIS 2.4 [repo](https://github.com/F5Networks/k8s-bigip-ctlr/releases/tag/v2.4.0)
* F5 IPAM Controller [repo](https://github.com/F5Networks/f5-ipam-controller/releases/tag/v0.1.2)

## Setup Options for the IPAM controller

CIS 2.4 provides the following options for using the F5 IPAM controller

* Defining the IPAM label in the service which maps to the IP-Range. In my example I am using the following 

  - ip-range='{"Test":"10.192.75.113-10.192.75.116","Production":"10.192.125.30-10.192.125.50"}'

In CIS 2.4 the F5 IPAM Controller can:

* Allocate IP address from static IP address pool based on the ipamlable defined in the service

**Note** The idea here is that you specify the ip-range label in the service and use service type load balancing. 

## Create the CIS Deployment Configuration

### Step 1

Add the parameter --ipam=true in the CIS deployment to provide the integration with CIS and IPAM

* --ipam=true

```
args: 
  - "--bigip-username=$(BIGIP_USERNAME)"
  - "--bigip-password=$(BIGIP_PASSWORD)"
  - "--bigip-url=192.168.200.60"
  - "--bigip-partition=k8s"
  - "--namespace=default"
  - "--pool-member-type=cluster"
  - "--flannel-name=fl-vxlan"
  - "--log-level=DEBUG"
  - "--insecure=true"
  - "--custom-resource-mode=true"
  - "--as3-validation=true"
  - "--log-as3-response=true"
  - "--ipam=true"
```

Deploy CIS and CRD schema

```
kubectl create -f f5-cluster-deployment.yaml
kubectl create -f customresourcedefinitions.yaml
```

* cis-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/servicetypelb/cis-deployment/f5-cluster-deployment.yaml)
* crd-schema [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/servicetypelb/crd-schema/customresourcedefinitions.yaml)

## F5 IPAM Deployment Configuration

### Step 2

* --orchestration=kubernetes

The orchestration parameter holds the orchestration environment i.e. Kubernetes

* --ip-range='{"Test":"10.192.75.113-10.192.75.116","Production":"10.192.125.30-10.192.125.50"}'

ip-range parameter holds the IP address ranges and from this range, it creates a pool of IP address range which gets allocated by the ipamlabel defined in the Service

* --log-level=debug

```
- args:
    - --orchestration=kubernetes
    - --ip-range='{"Test":"10.192.75.113-10.192.75.116","Production":"10.192.125.30-10.192.125.50"}'
    - --log-level=DEBUG
```

Deploy RBAC, schema and F5 IPAM Controller deployment

```
kubectl create -f f5-ipam-rbac.yaml
kubectl create -f f5-ipam-schema.yaml
kubectl create -f f5-ipam-deployment.yaml
```
## Logging output when deploying the F5 IPAM Controller

```
[kube@k8s-1-19-master crd-example]$ kubectl logs -f deploy/f5-ipam-controller -n kube-system
Found 2 pods, using pod/f5-ipam-controller-5d76c6f964-n9v6p
2021/04/20 17:10:47 [INFO] [INIT] Starting: F5 IPAM Controller - Version: 0.1.2, BuildInfo: azure-208-24641f25a94eadfef5ebd159315a091280e626a5
2021/04/20 17:10:47 [DEBUG] Creating IPAM Kubernetes Client
2021/04/20 17:10:47 [DEBUG] [ipam] Creating Informers for Namespace kube-system
2021/04/20 17:10:47 [DEBUG] Created New IPAM Client
2021/04/20 17:10:47 [DEBUG] [MGR] Creating Manager with Provider: f5-ip-provider
2021/04/20 17:10:47 [DEBUG] [STORE] [id ipaddress status ipam_label]
2021/04/20 17:10:47 [DEBUG] [STORE]  1   10.192.75.113 1 Test
2021/04/20 17:10:47 [DEBUG] [STORE]  2   10.192.75.114 1 Test
2021/04/20 17:10:47 [INFO] [CORE] Controller started
2021/04/20 17:10:47 [INFO] Starting IPAMClient Informer
2021/04/20 17:10:47 [DEBUG] [STORE]  3   10.192.75.115 1 Test
2021/04/20 17:10:47 [DEBUG] [STORE]  4   10.192.125.30 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  5   10.192.125.31 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  6   10.192.125.32 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  7   10.192.125.33 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  8   10.192.125.34 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  9   10.192.125.35 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  10  10.192.125.36 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  11  10.192.125.37 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  12  10.192.125.38 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  13  10.192.125.39 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  14  10.192.125.40 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  15  10.192.125.41 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  16  10.192.125.42 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  17  10.192.125.43 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  18  10.192.125.44 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  19  10.192.125.45 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  20  10.192.125.46 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  21  10.192.125.47 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  22  10.192.125.48 1 Production
2021/04/20 17:10:47 [DEBUG] [STORE]  23  10.192.125.49 1 Production
I0420 17:10:47.790510       1 shared_informer.go:240] Waiting for caches to sync for F5 IPAMClient Controller
2021/04/20 17:10:47 [DEBUG] Enqueueing on Create: kube-system/ipam.192.168.200.60.k8s
I0420 17:10:47.903745       1 shared_informer.go:247] Caches are synced for F5 IPAMClient Controller
2021/04/20 17:10:47 [DEBUG] K8S Orchestrator Started
2021/04/20 17:10:47 [DEBUG] Starting Custom Resource Worker
2021/04/20 17:10:47 [DEBUG] Starting Response Worker
2021/04/20 17:10:47 [DEBUG] Processing Key: &{0xc000154160 <nil> Create}
2021/04/20 17:12:35 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.200.60.k8s
2021/04/20 17:12:35 [DEBUG] Processing Key: &{0xc00055a840 0xc000154160 Update}
```

ipam-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/servicetypelb/ipam-deployment)


## Create the Service Type LoadBalancer Service

### Step 3

Create the pod deployments and services for the test and production application

```
kubectl create -f f5-demo-test-service.yaml
kubectl create -f f5-demo-production-service.yaml
```

pod-deployments [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/servicetypelb/pod-deployment)

## Logging output when the IPAM controller when the services are created

```
2021/04/27 20:46:11 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.200.60.k8s
2021/04/27 20:46:11 [DEBUG] Processing Key: &{0xc0002d4000 0xc0004ec2c0 Update}
2021/04/27 20:46:11 [DEBUG] [CORE] Allocated IP: 10.192.125.30 for Request:
Hostname:       Key: default/f5-demo-production_svc     CIDR:   IPAMLabel: Production   IPAddr:         Operation: Create
2021/04/27 20:46:11 [DEBUG] [PROV] Created 'A' Record. Host:default/f5-demo-production_svc, IP:10.192.125.30
2021/04/27 20:46:11 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.200.60.k8s
2021/04/27 20:46:11 [DEBUG] Processing Key: &{0xc0002d4160 0xc0002d4000 Update}
2021/04/27 20:46:11 [DEBUG] Updated: kube-system/ipam.192.168.200.60.k8s with Status. With IP: 10.192.125.30 for Request:
Hostname:       Key: default/f5-demo-production_svc     CIDR:   IPAMLabel: Production   IPAddr: 10.192.125.30   Operation: Create
2021/04/27 20:46:32 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.200.60.k8s
2021/04/27 20:46:32 [DEBUG] Processing Key: &{0xc00055a420 0xc0002d4160 Update}
2021/04/27 20:46:32 [DEBUG] [CORE] Allocated IP: 10.192.75.113 for Request:
Hostname:       Key: default/f5-demo-test_svc   CIDR:   IPAMLabel: Test IPAddr:         Operation: Create
2021/04/27 20:46:32 [DEBUG] [PROV] Created 'A' Record. Host:default/f5-demo-test_svc, IP:10.192.75.113
2021/04/27 20:46:32 [DEBUG] Updated: kube-system/ipam.192.168.200.60.k8s with Status. With IP: 10.192.75.113 for Request:
Hostname:       Key: default/f5-demo-test_svc   CIDR:   IPAMLabel: Test IPAddr: 10.192.75.113   Operation: Create
2021/04/27 20:46:32 [DEBUG] Enqueueing on Update: kube-system/ipam.192.168.200.60.k8s
2021/04/27 20:46:32 [DEBUG] Processing Key: &{0xc0002d4580 0xc00055a420 Update}
```

## View the F5 IPAM Controller configuration

F5 IPAM Controller creates the following CRD to create the configuration between CIS and IPAM 

```
[kube@k8s-1-19-master production]$ kubectl describe f5ipam -n kube-system
Name:         ipam.192.168.200.60.k8s
Namespace:    kube-system
Labels:       <none>
Annotations:  <none>
API Version:  fic.f5.com/v1
Kind:         F5IPAM
Metadata:
  Creation Timestamp:  2021-04-19T17:59:38Z
  Generation:          29
  Managed Fields:
    API Version:  fic.f5.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:spec:
    Manager:      k8s-bigip-ctlr
    Operation:    Update
    Time:         2021-04-19T20:15:18Z
    API Version:  fic.f5.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:status:
        .:
        f:IPStatus:
    Manager:      f5-ipam-controller
    Operation:    Update
    Time:         2021-04-27T20:46:32Z
    API Version:  fic.f5.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:spec:
        f:hostSpecs:
    Manager:         k8s-bigip-ctlr.real
    Operation:       Update
    Time:            2021-04-27T20:46:32Z
  Resource Version:  52405608
  Self Link:         /apis/fic.f5.com/v1/namespaces/kube-system/f5ipams/ipam.192.168.200.60.k8s
  UID:               611befc3-63e3-4558-858e-3868adf9bda4
Spec:
  Host Specs:
    Ipam Label:  Production
    Key:         default/f5-demo-production_svc
    Ipam Label:  Test
    Key:         default/f5-demo-test_svc
Status:
  IP Status:
    Ip:          10.192.125.30
    Ipam Label:  Production
    Key:         default/f5-demo-production_svc
    Ip:          10.192.75.113
    Ipam Label:  Test
    Key:         default/f5-demo-test_svc
Events:          <none>
[kube@k8s-1-19-master production]$
```

## View the Service Type LoadBalancer status

Use the kubectl get service command to determine the EXTERNAL-IP

```
[kube@k8s-1-19-master production]$ kubectl get service
NAME                 TYPE           CLUSTER-IP      EXTERNAL-IP     PORT(S)        AGE
f5-demo-production   LoadBalancer   10.111.34.124   10.192.125.30   80:31141/TCP   14m
f5-demo-test         LoadBalancer   10.96.155.107   10.192.75.113   80:30164/TCP   13m
```
CIS will add the EXTERNAL-IP to the BIG-IP as you can see in the diagram

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/servicetypelb/diagram/2021-04-27_14-15-10.png)
