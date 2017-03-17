FROM docker-registry.pdbld.f5net.com/velcro/alpine-golang-python:master

# To enable debug builds with this image, should add this
#   go install -race runtime/race
# But, it fails due to
# https://github.com/golang/go/issues/14481

COPY entrypoint.builder.sh /entrypoint.sh
COPY k8s-build-requirements.txt /tmp/k8s-build-requirements.txt
COPY k8s-runtime-requirements.txt /tmp/k8s-runtime-requirements.txt
COPY requirements.docs.txt /tmp/requirements.docs.txt
 
RUN apk add --no-cache \
		bash \
		git \
		make \
		su-exec && \
	pip install setuptools flake8 && \
	pip install -r /tmp/k8s-build-requirements.txt && \
	pip install -r /tmp/k8s-runtime-requirements.txt && \
	pip install -r /tmp/requirements.docs.txt && \
	git clone https://bldr-git.int.lineratesystems.com/mirror/gb.git $GOPATH/src/github.com/constabulary/gb && \
	git -C $GOPATH/src/github.com/constabulary/gb checkout 2b9e9134 && \
	go install github.com/constabulary/gb/... && \
	go get github.com/wadey/gocovmerge/... && \
	chmod 755 /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "/bin/bash" ]
