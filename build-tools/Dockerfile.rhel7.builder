FROM registry.redhat.io/rhel7

# GOLANG install steps

ENV GOLANG_VERSION 1.11.1
ENV GOLANG_SRC_URL https://golang.org/dl/go$GOLANG_VERSION.src.tar.gz
ENV GOLANG_SRC_SHA256 558f8c169ae215e25b81421596e8de7572bd3ba824b79add22fba6e284db1117

RUN REPOLIST=rhel-7-server-rpms,rhel-7-server-optional-rpms,rhel-server-rhscl-7-rpms && \
	yum -y update-minimal --disablerepo "*" --enablerepo rhel-7-server-rpms --setopt=tsflags=nodocs \
	  --security --sec-severity=Important --sec-severity=Critical && \
	yum -y install --disablerepo "*" --enablerepo ${REPOLIST} --setopt=tsflags=nodocs \
	  gcc openssl golang git make rsync wget python27 && \
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
	./make.bash && \
	yum -y erase golang && \
	yum clean all

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

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

# Controller install steps
COPY entrypoint.builder.sh /entrypoint.sh
COPY requirements.txt /tmp/requirements.txt
COPY requirements.docs.txt /tmp/requirements.docs.txt

RUN source scl_source enable python27 && \
	pip install --no-cache-dir --upgrade pip && \
	pip install --no-cache-dir setuptools flake8 && \
	pip install --no-cache-dir --ignore-installed -r /tmp/requirements.txt && \
	pip install --no-cache-dir -r /tmp/requirements.docs.txt && \
	go get github.com/wadey/gocovmerge && \
	go get golang.org/x/tools/cmd/cover && \
	go get github.com/mattn/goveralls && \
	go get github.com/onsi/ginkgo/ginkgo && \
	go get github.com/onsi/gomega && \
	chmod 755 /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "/bin/bash" ]
