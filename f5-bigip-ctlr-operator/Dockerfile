# Build the manager binary
FROM registry.redhat.io/openshift4/ose-helm-operator:v4.9

ENV HOME=/opt/helm
COPY f5-bigip-ctlr-operator/watches.yaml ${HOME}/watches.yaml
COPY helm-charts/f5-bigip-ctlr  ${HOME}/helm-charts/f5-bigip-ctlr
WORKDIR ${HOME}
