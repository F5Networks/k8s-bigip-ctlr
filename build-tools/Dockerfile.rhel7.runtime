FROM registry.redhat.io/rhel-atomic

LABEL name="f5networks/k8s-bigip-ctlr" \
      vendor="F5 Networks" \
      # version - should be passed in via docker build
      url="http://clouddocs.f5.com/products/connectors/k8s-bigip-ctlr/latest/" \
      summary="F5 BIG-IP Controller for Kubernetes" \
      description="Manages F5 BIG-IP from Kubernetes" \
      run='docker run --name ${NAME} ${IMAGE} /app/bin/k8s-bigip-ctlr' \
      io.k8s.description="Manages F5 BIG-IP from Kubernetes" \
      io.k8s.display-name="F5 BIG-IP Controller for Kubernetes" \
      io.openshift.expose-services="" \
      io.openshift.tags="f5,f5networks,bigip,openshift,router"

ENV APPPATH /app

RUN mkdir -p "$APPPATH/bin" \
 && chmod -R 755 "$APPPATH"

WORKDIR $APPPATH

COPY help.md /tmp/
COPY LICENSE /licenses/
COPY requirements.txt /tmp/requirements.txt

RUN microdnf --enablerepo=rhel-7-server-rpms --enablerepo=rhel-7-server-optional-rpms \
      --enablerepo=rhel-server-rhscl-7-rpms install --nodocs \
      golang-github-cpuguy83-go-md2man python27-python-pip git shadow-utils && \
    microdnf update && \
    go-md2man -in /tmp/help.md -out /help.1 && rm -f /tmp/help.md && \
    source scl_source enable python27 && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt && \
    python -m pip uninstall -y pip && \
    adduser ctlr && \
    microdnf remove golang-github-cpuguy83-go-md2man git fipscheck fipscheck-lib groff-base \
      less libedit libgnome-keyring openssh openssh-clients perl perl-Carp perl-Encode \
      perl-Error perl-Exporter perl-File-Path perl-File-Temp perl-Filter perl-Getopt-Long \
      perl-Git perl-HTTP-Tiny perl-PathTools perl-Pod-Escapes perl-Pod-Perldoc perl-Pod-Simple \
      perl-Pod-Usage perl-Scalar-List-Utils perl-Socket perl-Storable perl-TermReadKey \
      perl-Text-ParseWords perl-Time-HiRes perl-Time-Local perl-constant perl-libs perl-macros \
      perl-parent perl-podlators perl-threads perl-threads-shared rsync shadow-utils && \
    microdnf clean all

COPY bigip-virtual-server_v*.json $APPPATH/vendor/src/f5/schemas/
COPY as3-schema-3.11.0-3-cis.json $APPPATH/vendor/src/f5/schemas/
COPY k8s-bigip-ctlr $APPPATH/bin/k8s-bigip-ctlr.real
COPY VERSION_BUILD.json $APPPATH/vendor/src/f5/

# entrypoint to enable scl python at runtime
RUN echo $'#!/bin/sh\n\
	  source scl_source enable python27\n\
	  exec $APPPATH/bin/k8s-bigip-ctlr.real "$@"' > $APPPATH/bin/k8s-bigip-ctlr && \
    chmod +x $APPPATH/bin/k8s-bigip-ctlr

USER ctlr

# Run the run application in the projects bin directory.
CMD [ "/app/bin/k8s-bigip-ctlr" ]
