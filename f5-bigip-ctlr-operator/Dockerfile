# Build the manager binary
FROM registry.redhat.io/openshift4/ose-helm-operator:latest

ENV HOME=/opt/helm

### Required OpenShift Labels
LABEL name="F5 Container Ingress Services Operator" \
      maintainer="f5_cis_operators@f5.com" \
      vendor="F5 Networks Inc." \
      version="v3.0.0" \
      release="1" \
      summary="Container Ingress Services Operator for F5 BIG-IP Next" \
      description="F5 BIG-IP Next Controller Operator is a Service Operator which installs F5 BIG-IP Controller (Container Ingress Services) on Kubernetes and OpenShift platforms and respective supported versions."

# Required Licenses
COPY f5-bigip-ctlr-operator/licenses /licenses

COPY f5-bigip-ctlr-operator/watches.yaml ${HOME}/watches.yaml
COPY helm-charts/f5-bigip-ctlr  ${HOME}/helm-charts/f5-bigip-ctlr
WORKDIR ${HOME}
