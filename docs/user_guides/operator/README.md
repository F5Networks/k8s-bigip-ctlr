# Installing the F5 Container Ingress Services Operator in OpenShift

## OpenShift Operator user-guides and testing

In OpenShift, CIS can be installed manually using a a yaml deployment manifest or using the Operator in OpenShift. The CIS Operator is a packaged deployment of CIS and will use Helm Charts to create the deployment. This user-guide provide additional information and examples when using the CIS Operator in OpenShift.

Demo on YouTube [video](https://youtu.be/hhC-u-ehOuw)

### Prerequisites

Create BIG-IP login credentials for use with Operator Helm charts

    oc create secret generic bigip-login  -n kube-system --from-literal=username=admin  --from-literal=password=<secret>

### Step 1

Locate the F5 Container Ingress Services Operator in OpenShift OperatorHub as shown in the diagram below. Recommend search for F5 

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-10_12-59-30.png)

### Step 2

Select the Operator to Install. In this example I am installing the latest Operator 1.7.0. Select the Install tab as shown in the diagram

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-10_13-20-27.png)

### Step 3

Install the Operator and provide the installation mode, installed namespaces and approval strategy. In this user-guide and demo I am using the defaults

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-10_13-47-45.png)

Operator will take a few minutes to install

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-10_13-50-10.png)

Once installed select the View Operator tab

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-10_13-51-02.png)

### Step 4

Now that the operator is installed you can create an instance of CIS. This will deploy CIS in OpenShift

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-14_14-07-36.png)

Note that currently some fields may not be represented in form so its best to use the "YAML View" for full control of object creation. Select the "YAML View"

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-14_14-14-41.png)

### Step 5

Enter requirement objects in the YAML View. Please add the recommended setting below:

* Remove **agent as3** as this is default
* Change repo image to **f5networks/cntr-ingress-svcs**. By default OpenShift will pull the image from Docker. 
* Change the user to **registry.connect.redhat.com** so OpenShift will be pull the published image from the RedHat Ecosystem Catalog [repo](https://catalog.redhat.com/software/containers/f5networks/cntr-ingress-svcs/5ec7ad05ecb5246c0903f4cf)


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
    log_level: DEBUG
    route_vserver_addr: 10.192.75.109
    bigip_partition: OpenShift
    openshift_sdn_name: /Common/openshift_vxlan
    bigip_url: 10.192.75.60
    insecure: true
    pool-member-type: cluster
  bigip_login_secret: bigip-login
  image:
    pullPolicy: Always
    repo: f5networks/cntr-ingress-svcs
    user: registry.connect.redhat.com
  namespace: kube-system
  rbac:
    create: true
  resources: {}
  serviceAccount:
    create: true
  version: latest
```

Select the Create tab

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-14_14-38-24.png)

### Step 6

Validate CIS deployment. Select Workloads/Deployments 

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-14_14-42-54.png)

Select the **f5-bigip-ctlr-operator** to see more details on the CIS deployment. Also validate the CIS deployment image

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/operator/diagrams/2021-06-14_14-45-08.png)

CIS deployment is ready to receive OpenShift Routes! 
