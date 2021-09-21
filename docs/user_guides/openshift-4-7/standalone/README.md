# OpenShift 4.8 and F5 Container Ingress Services (CIS) User-Guide for Standalone BIG-IP using OVN-Kubernetes Advanced Networking

This user guide is create to document OpenShift 4.8 integration of CIS and standalone BIG-IP using OVN-Kubernetes advanced networking. This user guide provides configuration for a standalone BIG-IP with **OVN-Kubernetes hybrid overlay feature(VxLAN)**. OVN-Kubernetes hybrid overlay uses the GENEVE protocol for EAST/WEST traffic within the OpenShift Cluster and VxLAN tunnels to network BIG-IP devices.

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/diagram/2021-08-03_23-17-10.png)

Demo on YouTube [video](https://youtu.be/0YpdX1nhycA)

RedHat documents the installation of **OVN-K8S advanced networking** in the [specifying advanced network configuration sections](https://docs.openshift.com/container-platform/4.8/installing/installing_vsphere/installing-vsphere-installer-provisioned-network-customizations.html#modifying-nwoperator-config-startup_installing-vsphere-installer-provisioned-network-customizations) of the install process. Based on the following note from RedHat, its very important to follow the installation of OVN-Kubernetes Hybrid Overlay Feature when installing OpenShift. Modification, migration cannot be applied once OpenShift is already installed.

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/diagram/2021-08-03_13-12-08.png)

### Prerequisites

You have created the **install-config.yaml** file with the required modifications. When creating the install-config.yaml, change the default networkType: **OpenShiftSDN** to networkType: **OVNKubernetes**

### Procedure

**Step 1:** Create install-config.yaml

```
# ./openshift-install create install-config --dir=ipi
? Platform vsphere
? vCenter vcsa7-pme.f5demo.com
? Username administrator@f5demo.com
? Password [? for help] *********
INFO Connecting to vCenter vcsa7-pme.f5demo.com
? Datacenter PME-LAB
? Cluster OCP-PM
? Default Datastore datastore1 (3)
? Network VM Network
? Virtual IP Address for API 10.192.125.101
? Virtual IP Address for Ingress 10.192.125.102
? Base Domain f5demo.com
? Cluster Name ocp-pm
? Pull Secret [? for help] ......
INFO Install-Config created in: ipi
```
install-config.yaml.yaml [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/openshift/install-config.yaml)

**Step 2:** Create manifests

```
# ./openshift-install create manifests --dir=ipi
INFO Consuming Install Config from target directory
INFO Manifests created in: ipi/manifests and ipi/openshift

# ls
04-openshift-machine-config-operator.yaml  cluster-infrastructure-02-config.yml  cluster-proxy-01-config.yaml     kube-system-configmap-root-ca.yaml
cloud-provider-config.yaml                 cluster-ingress-02-config.yml         cluster-scheduler-02-config.yml  machine-config-server-tls-secret.yaml
cluster-config.yaml                        cluster-network-01-crd.yml            cvo-overrides.yaml               openshift-config-secret-pull-secret.yaml
cluster-dns-02-config.yml                  cluster-network-02-config.yml         kube-cloud-config.yaml           openshift-kubevirt-infra-namespace.yaml
```

**Step 3:** Copy cluster-network-03-config.yaml to manifests directory

RedHat documentation for [configuring hybrid networking with OVN-Kubernetes](https://docs.openshift.com/container-platform/4.8/networking/ovn_kubernetes_network_provider/configuring-hybrid-networking.html#configuring-hybrid-ovnkubernetes_configuring-hybrid-networking)

Create a stub manifest file for the advanced network configuration that is named cluster-network-03-config.yml in the <installation_directory>/manifests/ directory. The defaultNetwork: hybridOverlayConfig: {} is required

```
# cat cluster-network-03-config.yaml
apiVersion: operator.openshift.io/v1
kind: Network
metadata:
  name: cluster
spec:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  serviceNetwork:
  - 172.30.0.0/16
  defaultNetwork:
    ovnKubernetesConfig:
      hybridOverlayConfig: {}
    type: OVNKubernetes

# cp cluster-network-03-config.yaml /openshift/ipi/manifests/
```
cluster-network-03-config.yaml [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/openshift/cluster-network-03-config.yaml)

**Step 4:** Create Cluster

You ready to create the OpenShift cluster

```
# ./openshift-install create cluster --dir=ipi
INFO Consuming Worker Machines from target directory
INFO Consuming OpenShift Install (Manifests) from target directory
INFO Consuming Openshift Manifests from target directory
INFO Consuming Master Machines from target directory
INFO Consuming Common Manifests from target directory
INFO Creating infrastructure resources...
INFO Waiting up to 20m0s for the Kubernetes API at https://api.ocp-pm.f5demo.com:6443...
INFO API v1.21.1+8268f88 up
INFO Waiting up to 30m0s for bootstrapping to complete...
INFO Destroying the bootstrap resources...
INFO Waiting up to 40m0s for the cluster at https://api.ocp-pm.f5demo.com:6443 to initialize...
INFO Waiting up to 10m0s for the openshift-console route to be created...
INFO Install complete!
INFO To access the cluster as the system:admin user when using 'oc', run 'export KUBECONFIG=/openshift/ipi/auth/kubeconfig'
INFO Access the OpenShift web-console here: https://console-openshift-console.apps.ocp-pm.f5demo.com
INFO Login to the console with user: "kubeadmin", and password: "secret"
INFO Time elapsed: 26m50s
#
```

**Step 5:** Validate **defaultNetwork: hybridOverlayConfig** was configured correctly during OpenShift installation

```
# oc --kubeconfig /openshift/ipi/auth/kubeconfig get networks.operator.openshift.io cluster -o yaml
apiVersion: operator.openshift.io/v1
kind: Network
metadata:
  annotations:
    networkoperator.openshift.io/ovn-cluster-initiator: 10.192.125.160
  creationTimestamp: "2021-08-03T06:50:15Z"
  generation: 53
  name: cluster
  resourceVersion: "22347"
  uid: 8942ef7d-31e7-4dde-8873-685d9231b891
spec:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  defaultNetwork:
    ovnKubernetesConfig:
      genevePort: 6081
      hybridOverlayConfig: {} --- Shows the correct configuration for hybrid networking
      mtu: 1400
      policyAuditConfig:
        destination: "null"
        maxFileSize: 50
        rateLimit: 20
        syslogFacility: local0
    type: OVNKubernetes
  deployKubeProxy: false
  disableMultiNetwork: false
  disableNetworkDiagnostics: false
  logLevel: Normal
  managementState: Managed
  observedConfig: null
  operatorLogLevel: Normal
  serviceNetwork:
  - 172.30.0.0/16
  unsupportedConfigOverrides: null
  useMultiNetworkPolicy: false
```

## Create a BIG-IP VXLAN tunnel for OVN-Kubernetes Advanced Networking

### Procedure

**Step 1:** Create tunnel profile

    (tmos)# create net tunnels vxlan vxlan-mp flooding-type multipoint

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/diagram/2021-08-03_14-18-36.png)

    (tmos)# create net tunnels tunnel openshift_vxlan key 4097 profile vxlan-mp local-address 10.192.125.60

**Note:** OpenShift uses 4097(VNI) for VxLAN communication

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/diagram/2021-08-03_14-20-34.png)

### Step 2: Create self-ip for CNI

    (tmos)# create net self 10.142.2.60/12 allow-service all vlan openshift_vxlan

**Note:** Use self IP range (10.142.2.60/12) which supernets the OpenShift cluster network i.e 10.128.0.0/14 to differentiate the VxLAN and GENEVE communication.

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/diagram/2021-08-03_14-39-20.png)

Diagram of all the BIG-IP self-ip addresses

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/diagram/2021-08-03_14-40-06.png)

## Create a partition on BIG-IP for CIS to manage

### Procedure

    (tmos)# create auth partition OpenShift

This needs to match the partition in the controller configuration created by the CIS Operator

## Create CIS Controller, BIG-IP credentials and RBAC Authentication

### Procedure

Since CIS is using the AS3 declarative API we need the AS3 extension installed on BIG-IP. Follow the link to install AS3
 
* Install AS3 on BIG-IP
https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/installation.html

Create f5-bigip-deployment manifests

```
# oc create secret generic bigip-login --namespace kube-system --from-literal=username=admin --from-literal=password=<secret>
# oc create serviceaccount bigip-ctlr -n kube-system
# oc create -f f5-openshift-clusterrole.yaml
# oc create -f f5-bigip-deployment.yaml
# oc adm policy add-cluster-role-to-user cluster-admin -z bigip-ctlr -n kube-system
```

cis-deployment [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/tree/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/cis)

## Add OVN-Kubernetes advanced networking CNI specific annotations

### Procedure

You need to add OVN-Kubernetes advanced networking CNI specific annotations to all namespace that CIS is monitoring and configuring on BIG-IP. This user-guide uses the **namespace default**

```
apiVersion: v1
kind: Namespace
metadata:
  name: default
  annotations:
    k8s.ovn.org/hybrid-overlay-external-gw: 10.142.2.60 #self ip of Vxlan tunnel
    k8s.ovn.org/hybrid-overlay-vtep: 10.192.125.60 #BIG-IP interface address rotatable to the OpenShift nodes
```

    # oc apply -f ocp-exgw.yaml

ocp-exgw.yaml [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/openshift/ocp-exgw.yaml)

## Installing the Demo App in OpenShift and validate the OVN-Kubernetes advanced networking annotations

### Procedure

Deploy demo app in OpenShift

    # oc create -f demo-app/

Validated deployed demo apps in OpenShift

```
# oc get pod
NAME                      READY   STATUS    RESTARTS   AGE
f5-demo-9498f95fc-5fnj5   1/1     Running   0          34s
f5-demo-9498f95fc-62g4l   1/1     Running   0          34s
f5-demo-9498f95fc-qdl8b   1/1     Running   0          34s
f5-demo-9498f95fc-zswjd   1/1     Running   0          34s
```

Validated OVN-Kubernetes advanced networking annotations applied to the deployed application pod. As you can see below the deployed pod has added annotations for **k8s.ovn.org/hybrid-overlay-external-gw: 10.142.2.60** using the BIG-IP vtep **k8s.ovn.org/hybrid-overlay-vtep: 10.192.125.60**

```
# oc describe pod f5-demo-9498f95fc-5fnj5
Name:         f5-demo-9498f95fc-5fnj5
Namespace:    default
Priority:     0
Node:         ocp-pm-2zxp2-worker-9bn9s/10.192.125.165
Start Time:   Tue, 03 Aug 2021 00:27:45 -0700
Labels:       app=f5-demo
              pod-template-hash=9498f95fc
Annotations:  k8s.ovn.org/hybrid-overlay-external-gw: 10.142.2.60
              k8s.ovn.org/hybrid-overlay-vtep: 10.192.125.60
              k8s.ovn.org/pod-networks:
                {"default":{"ip_addresses":["10.128.2.18/23"],"mac_address":"0a:58:0a:80:02:12","gateway_ips":["10.128.2.3"],"routes":[{"dest":"10.128.0.0...
              k8s.v1.cni.cncf.io/network-status:
                [{
                    "name": "ovn-kubernetes",
                    "interface": "eth0",
                    "ips": [
                        "10.128.2.18"
                    ],
                    "mac": "0a:58:0a:80:02:12",
                    "default": true,
                    "dns": {}
                }]
              k8s.v1.cni.cncf.io/networks-status:
                [{
                    "name": "ovn-kubernetes",
                    "interface": "eth0",
                    "ips": [
                        "10.128.2.18"
                    ],
                    "mac": "0a:58:0a:80:02:12",
                    "default": true,
                    "dns": {}
                }]
Status:       Running
IP:           10.128.2.18
IPs:
  IP:           10.128.2.18
Controlled By:  ReplicaSet/f5-demo-9498f95fc
Containers:
  f5-demo:
    Container ID:   cri-o://51c6fff708dca44b5448f6604b3aff0ae8da3d98c3bead99a4b4098ed52902c7
    Image:          f5devcentral/f5-demo-httpd
    Image ID:       docker.io/f5devcentral/f5-demo-httpd@sha256:1c86ba346fa766356365f2f05bc3be6c2cdd5eb69552ce3867091c9a38d6ee2b
    Port:           80/TCP
    Host Port:      0/TCP
    State:          Running
      Started:      Tue, 03 Aug 2021 00:27:56 -0700
    Ready:          True
    Restart Count:  0
    Environment:
      service_name:  f5-demo
    Mounts:
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-rmggv (ro)
Conditions:
  Type              Status
  Initialized       True
  Ready             True
  ContainersReady   True
  PodScheduled      True
Volumes:
  kube-api-access-rmggv:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  3607
    ConfigMapName:           kube-root-ca.crt
    ConfigMapOptional:       <nil>
    DownwardAPI:             true
    ConfigMapName:           openshift-service-ca.crt
    ConfigMapOptional:       <nil>
QoS Class:                   BestEffort
Node-Selectors:              <none>
Tolerations:                 node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                             node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:
  Type    Reason          Age   From               Message
  ----    ------          ----  ----               -------
  Normal  Scheduled       48s   default-scheduler  Successfully assigned default/f5-demo-9498f95fc-5fnj5 to ocp-pm-2zxp2-worker-9bn9s
  Normal  AddedInterface  46s   multus             Add eth0 [10.128.2.18/23] from ovn-kubernetes
  Normal  Pulling         46s   kubelet            Pulling image "f5devcentral/f5-demo-httpd"
  Normal  Pulled          39s   kubelet            Successfully pulled image "f5devcentral/f5-demo-httpd" in 7.503713793s
  Normal  Created         38s   kubelet            Created container f5-demo
  Normal  Started         38s   kubelet            Started container f5-demo
#
```

## Create Route for Ingress traffic to Demo App

Create basic route for Ingress traffic from BIG-IP to Demo App 

    # oc create -f f5-demo-route-basic.yaml


f5-demo-route-basic [repo](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/route/f5-demo-route-basic.yaml)

Validate the route via the OpenShift UI under the Networking/Routes

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-7/standalone/diagram/2021-06-30_13-59-43.png)

Validate the route via the BIG-IP

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/openshift-4-8/standalone-ovn-k8s-hybrid/diagram/2021-08-03_22-39-35.png)
