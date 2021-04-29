FROM quay.io/operator-framework/helm-operator:v1.6.2

### Required OpenShift Labels
LABEL name="F5 BIG-IP Controller Operator" \
      vendor="F5 Networks Inc" \
      version="v1.7.0" \
      release="1" \
      summary="F5 BIG-IP Controller Operator" \
      description="This operator will deploy F5 BIG-IP Controller for Kubernetes and OpenShift into the cluster."

# Required Licenses
COPY licenses /licenses

COPY watches.yaml ${HOME}/watches.yaml
COPY helm-charts/ ${HOME}/helm-charts/
