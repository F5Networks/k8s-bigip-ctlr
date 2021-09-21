# BIG-IP Metrics from Prometheus using Telemetry Streaming and Container Ingress Services

Prometheus is an open source monitoring framework. This user-guide covers setup of Prometheus for BIG-IP and CIS using F5 Telemetry Streaming. In this user-guide, Prometheus is deployed in Kubernetes and configured via a ConfigMap. BIG-IP is load balancing the management traffic to the Prometheus-UI via an Ingress automated via CIS as shown in the diagram below.

![diagram](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/prometheus/diagrams/2021-06-03_14-03-16.png)

Demo on YouTube [video](https://www.youtube.com/watch?v=efN4fXWjkUo)

## How to Setup Prometheus Monitoring On Kubernetes Cluster

### Create a Namespace and ClusterRole

Create a Kubernetes namespace for all our monitoring components
```
kubectl create namespace monitoring
```
Create a file named clusterRole.yaml. Locate the clusterRole.yaml file from my repo [yaml](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/prometheus/prometheus-deployment/clusterRole.yaml)
```
kubectl create -f clusterRole.yaml
```

### Create a ConfigMap

Create a ConfigMap with all the prometheus scrape config and alerting rules, which will be mounted to the Prometheus container in /etc/prometheus as prometheus.yaml and prometheus.rules files

Create a file called config-map.yaml. Locate the config-map.yaml file from my repo [yaml](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/prometheus/prometheus-deployment/config-map.yaml)
```
kubectl create -f config-map.yaml
```
The prometheus.yaml contains all the configuration to dynamically discover pods and services running in the Kubernetes cluster. We have the following scrape jobs in our Prometheus scrape configuration. For more information review the following from devopscube.com [link](https://devopscube.com/setup-prometheus-monitoring-on-kubernetes/)

### Create a Prometheus Deployment

Create a file named prometheus-deployment.yaml. Locate the prometheus-deployment.yaml file from my repo [yaml](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/prometheus/prometheus-deployment/prometheus-deployment.yaml)
```
kubectl create  -f prometheus-deployment.yaml
```
You can check the created deployment using the following command
```
[kube@k8s-1-18-master prometheus]$ kubectl get deployments --namespace=monitoring
NAME                    READY   UP-TO-DATE   AVAILABLE   AGE
prometheus-deployment   1/1     1            1           10d
[kube@k8s-1-18-master prometheus]$
```

## Connecting To Prometheus Dashboard via F5 Container Ingress Services

Connect to the Prometheus dashboard by exposing the Prometheus deployment as a service with F5 Load Balancer using Container Ingress Services

### Create a file named prometheus-service.yaml

We will expose Prometheus using ClusterIP. ClusterIP allows the BIG-IP to forward traffic directly to the Prometheus pod bypassing kube-proxy. Use ClusterIP type, which will create a F5 BIG-IP load balancer and points it to the service
```
apiVersion: v1
kind: Service
metadata:
  name: prometheus-service
  namespace: monitoring
  annotations:
      prometheus.io/scrape: 'true'
      prometheus.io/port:   '9090'
spec:
  selector: 
    app: prometheus-server
  type: ClusterIP 
  ports:
    - port: 8080
      targetPort: 9090
```
The annotations in the above service YAML makes sure that the service endpoint is scrapped by Prometheus. The prometheus.io/port should always be the target port mentioned in service YAML

Create the service using the following command. Locate the prometheus-service.yaml file from my repo [yaml](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/prometheus/prometheus-deployment/prometheus-service.yaml)

```
kubectl create -f prometheus-service.yaml -n monitoring
```

### Create a file named prometheus-ingress.yaml for Container Ingress Services

Create a Ingress resource for Container Ingress Services to configure F5 BIG-IP

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: prometheus-ui
  namespace: monitoring
  annotations:
    virtual-server.f5.com/ip: "10.192.75.107"
    virtual-server.f5.com/clientssl: '[ { "hosts": [ "prometheus.f5demo.com" ], "bigIpProfile": "/Common/clientssl" } ]'
    virtual-server.f5.com/https-port: "443"
    ingress.kubernetes.io/ssl-redirect: "true"
spec:
  rules:
  - host: prometheus.f5demo.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: prometheus-service
            port:
              number: 8080
```
The annotations in the above Ingress provides the public virtual-IP used to connect the prometheus-ui. BIG-IP will terminate SSL and work traffic to the pod on port 8080. You can also add additional security setting to the Ingress resource to prevent the prometheus-ui from web attacks.

Create the Ingress using the following command. Locate the prometheus-ingress.yaml file from my repo [yaml](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/prometheus/prometheus-deployment/prometheus-ingress.yaml)

```
kubectl create -f prometheus-ingress.yaml -n monitoring
```
Once created, you can access the Prometheus dashboard using the virtual IP address

![Image of CRDs](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/prometheus/diagrams/2020-05-11_16-28-32.png)

## Configure BIG-IP Telemetry Streaming for Prometheus

Support for the Prometheus pull consumer is available in TS 1.12.0 and later

Install telemetry streaming rpm package on BIG-IP. Following link explains how to install the rpm on BIG-IP [Downloading and installing Telemetry Streaming](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/installation.html)

Download the latest Telemetry Streaming following link [rpm](https://github.com/F5Networks/f5-telemetry-streaming/releases/tag/v1.20.0)

## Configure Telemetry Streaming declaration

This example shows how to use the Prometheus pull consumer. For this pull consumer, the type
must be Prometheus in the Pull Consumer class as shown
```
{
    "class": "Telemetry",
    "My_Poller": {
        "class": "Telemetry_System_Poller",
        "interval": 0
    },
    "My_System": {
        "class": "Telemetry_System",
        "enable": "true",
        "systemPoller": [
            "My_Poller"
        ]
    },
    "metrics": {
        "class": "Telemetry_Pull_Consumer",
        "type": "Prometheus",
        "systemPoller": "My_Poller"
    }
}
```
The Prometheus Pull Consumer outputs the telemetry data according to the Prometheus data
model specification configured in Prometheus

## Create Prometheus user on BIG-IP

Create a user for basic_auth allowing Prometheus access to the metrics_path

### Configure Prometheus

Since we created a config map with all the prometheus scrape config and alerting rules, it be mounted to the Prometheus container in /etc/prometheus as prometheus.yaml and prometheus.rules files.

``` 
      - job_name: 'BIGIP - TS'
        scrape_timeout: 30s
        scrape_interval: 30s
        scheme: https

        tls_config:
          insecure_skip_verify: true

        metrics_path: '/mgmt/shared/telemetry/pullconsumer/metrics'
        basic_auth:
          username: 'prometheus'
          password: 'secret'
        static_configs:
        - targets: ['192.168.200.60']

      - job_name: cis
        scrape_interval: 10s
        metrics_path: '/metrics'
        kubernetes_sd_configs:
          - role: pod
        relabel_configs:
          - source_labels: [__meta_kubernetes_namespace]
            action: replace
            target_label: k8s_namespace
          - source_labels: [__meta_kubernetes_pod_name]
            action: replace
            target_label: k8s_pod_name
          - source_labels: [__address__]
            action: replace
            regex: ([^:]+)(?::\d+)?
            replacement: ${1}:8080
            target_label: __address__
          - source_labels: [__meta_kubernetes_pod_label_app]
            action: keep
            regex: k8s-bigip-ctlr
```
Add BIG-IP and CIS job_name to the config-map.yaml so it applies the configuration Prometheus.yaml. Re-apply the Prometheus deployment and ConfigMap

**Field description**

* scheme: How prometheus will connect to the polled deviceConfig
* tls_config: - Is where you  disable SSL certificate validation
* metrics path:  - the path used to retrieve metrics from the BIG-IP
* basic_auth: - credentials for Prometheus to authenticate to the BIG-IP
* static_configs: - Contains one or more targets for this prometheus job

Check the targets Prometheus dashboard to make sure Prometheus is able to pull BIG-IP and CIS

![Image of Target](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/prometheus/diagrams/2021-06-03_15-09-19.png)

There are many metrics available to graph or monitor. Example below virtualServers current connections. Use the label to graph the metric desired.
```
# HELP f5_clientside_curConns clientside.curConns
# TYPE f5_clientside_curConns gauge
f5_clientside_curConns{virtualServers="/k8s_AS3/Shared/ingress_10_192_75_107_80"} 0
f5_clientside_curConns{virtualServers="/k8s_AS3/Shared/ingress_10_192_75_107_443"} 8
f5_clientside_curConns{virtualServers="/k8s_AS3/Shared/ingress_10_192_75_108_80"} 0
```
Graph displaying concurrent connection

![Image of graph](https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/prometheus/diagrams/2020-05-12_16-08-21.png)
