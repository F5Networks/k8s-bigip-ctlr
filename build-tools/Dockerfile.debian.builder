FROM python:3.6-slim-buster

# gcc for cgo
RUN apt-get update && apt-get install -y --no-install-recommends \
		g++ \
		gcc \
		libc6-dev \
		make \
		pkg-config \
		wget \
		bash \
		git \
		rsync \
		procps \
	&& rm -rf /var/lib/apt/lists/*

ENV GOLANG_VERSION 1.15

# licensee dependencies
RUN apt-get update && apt-get install -y ruby bundler cmake pkg-config git libssl-dev libpng-dev
RUN gem install licensee

RUN set -eux; \
	\
# this "case" statement is generated via "update.sh"
	dpkgArch="$(dpkg --print-architecture)"; \
	case "${dpkgArch##*-}" in \
		amd64) goRelArch='linux-amd64'; goRelSha256='2d75848ac606061efe52a8068d0e647b35ce487a15bb52272c427df485193602' ;; \
        armhf) goRelArch='linux-armv6l'; goRelSha256='6d8914ddd25f85f2377c269ccfb359acf53adf71a42cdbf53434a7c76fa7a9bd' ;; \
        arm64) goRelArch='linux-arm64'; goRelSha256='7e18d92f61ddf480a4f9a57db09389ae7b9dadf68470d0cb9c00d734a0c57f8d' ;; \
        i386) goRelArch='linux-386'; goRelSha256='68ce979083126694ceef60233f69efe870f54af24d81a120f76265107a9e9aab' ;; \
        ppc64el) goRelArch='linux-ppc64le'; goRelSha256='4603736a158b3d8ac52b9245f39bf715936c801e05bb5ad7c44b1edd6d5ef6a2' ;; \
        s390x) goRelArch='linux-s390x'; goRelSha256='8825f93caaf87465e32f298408c48b98d4180f3ddb885bd027f2926e711d23e8' ;; \
        *) goRelArch='src'; goRelSha256='69438f7ed4f532154ffaf878f3dfd83747e7a00b70b3556eddabf7aaee28ac3a'; \
            echo >&2; echo >&2 "warning: current architecture ($dpkgArch) does not have a corresponding Go binary release; will be building from source"; echo >&2 ;; \
    esac; \
    \
	url="https://golang.org/dl/go${GOLANG_VERSION}.${goRelArch}.tar.gz"; \
	wget -O go.tgz "$url"; \
	echo "${goRelSha256} *go.tgz" | sha256sum -c -; \
	tar -C /usr/local -xzf go.tgz; \
	rm go.tgz; \
	\
	if [ "$goRelArch" = 'src' ]; then \
		echo >&2; \
		echo >&2 'error: UNIMPLEMENTED'; \
		echo >&2 'TODO install golang-any from jessie-backports for GOROOT_BOOTSTRAP (and uninstall after build)'; \
		echo >&2; \
		exit 1; \
	fi; \
	\
	export PATH="/usr/local/go/bin:$PATH"; \
	go version

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

# Controller install steps
COPY entrypoint.builder.sh /entrypoint.sh
COPY requirements.txt /tmp/requirements.txt
COPY requirements.docs.txt /tmp/requirements.docs.txt
RUN pip install --no-cache-dir --upgrade pip==20.0.2 && \
    pip install --no-cache-dir setuptools flake8 virtualenv && \
	pip install --no-cache-dir -r /tmp/requirements.txt && \
	pip install --no-cache-dir -r /tmp/requirements.docs.txt && \
	go get github.com/wadey/gocovmerge && \
	go get golang.org/x/tools/cmd/cover && \
	go get github.com/mattn/goveralls && \
	go get github.com/onsi/ginkgo/ginkgo && \
	go get github.com/onsi/gomega && \
	chmod 755 /entrypoint.sh

COPY --from=gosu/assets /opt/gosu /opt/gosu
RUN set -x \
    && /opt/gosu/gosu.install.sh \
    && rm -fr /opt/gosu

ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "/bin/bash" ]
