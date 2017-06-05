FROM registry.access.redhat.com/rhel7

# GOLANG install steps used from the official golang:1.7-alpine image
# at https://github.com/docker-library/golang/tree/f19fa68b57e811315e95091bb6b78c1e2f43d14f

ENV GOLANG_VERSION 1.7.5
ENV GOLANG_SRC_URL https://golang.org/dl/go$GOLANG_VERSION.src.tar.gz
ENV GOLANG_SRC_SHA256 4e834513a2079f8cbbd357502cccaac9507fd00a1efe672375798858ff291815

### IS THIS NECESSARY w/ CENTOS/RHEL?
# https://golang.org/issue/14851
#COPY no-pic.patch /
# https://golang.org/issue/17847
#COPY 17847.patch /

RUN	yum clean all && \
	REPOLIST=rhel-7-server-rpms,rhel-7-server-optional-rpms,rhel-server-rhscl-7-rpms && \
    yum -y update-minimal --disablerepo "*" --enablerepo ${REPOLIST} --setopt=tsflags=nodocs \
	  --security --sec-severity=Important --sec-severity=Critical && \
	yum -y install --disablerepo "*" --enablerepo ${REPOLIST} --setopt=tsflags=nodocs \
	  golang-github-cpuguy83-go-md2man gcc openssl golang git make wget python27 && \
#	  golang-github-cpuguy83-go-md2man gcc openssl golang git make wget patch python27 && \
# Add epel repo for dpkg install
	curl -o epel-release-latest-7.noarch.rpm -SL https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
            --retry 9 --retry-max-time 0 -C - && \
    rpm -ivh epel-release-latest-7.noarch.rpm && rm epel-release-latest-7.noarch.rpm && \
	yum -y install --disablerepo "*" --enablerepo epel --setopt=tsflags=nodocs dpkg && \
	export GOROOT_BOOTSTRAP="$(go env GOROOT)" && \
	wget -q "$GOLANG_SRC_URL" -O golang.tar.gz && \
	echo "$GOLANG_SRC_SHA256  golang.tar.gz" | sha256sum -c - && \
	tar -C /usr/local -xzf golang.tar.gz && \
	rm golang.tar.gz && \
	cd /usr/local/go/src && \
#	patch -p2 -i /no-pic.patch && \
#	patch -p2 -i /17847.patch && \
#	rm -rf /*.patch && \
	./make.bash && \
	yum -y erase golang && \
	yum clean all

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

# Controller install steps
COPY entrypoint.builder.sh /entrypoint.sh
COPY k8s-build-requirements.txt /tmp/k8s-build-requirements.txt
COPY k8s-runtime-requirements.txt /tmp/k8s-runtime-requirements.txt
COPY requirements.docs.txt /tmp/requirements.docs.txt

RUN source scl_source enable python27 && \
	pip install --upgrade pip && \
	pip install setuptools flake8 && \
	pip install -r /tmp/k8s-build-requirements.txt && \
	pip install -r /tmp/k8s-runtime-requirements.txt && \
	pip install -r /tmp/requirements.docs.txt

RUN	go get github.com/wadey/gocovmerge && \
	git clone https://bldr-git.int.lineratesystems.com/mirror/gb.git $GOPATH/src/github.com/constabulary/gb && \
	git -C $GOPATH/src/github.com/constabulary/gb checkout 2b9e9134 && \
	go install github.com/constabulary/gb/... && \
	chmod 755 /entrypoint.sh

# install gosu
# https://github.com/tianon/gosu/blob/master/INSTALL.md#from-centos
ENV GOSU_VERSION 1.10
RUN set -ex && \
	dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')" && \
	wget -O /usr/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch" && \
	wget -O /tmp/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc" && \
# verify the signature
	export GNUPGHOME="$(mktemp -d)" && \
	gpg --keyserver ha.pool.sks-keyservers.net --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 && \
	gpg --batch --verify /tmp/gosu.asc /usr/bin/gosu && \
	rm -r "$GNUPGHOME" /tmp/gosu.asc && \
	chmod +x /usr/bin/gosu && \
# verify that the binary works
	gosu nobody true

ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "/bin/bash" ]
