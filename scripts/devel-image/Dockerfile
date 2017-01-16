FROM golang:1.6

RUN set -x && \
  apt-get update && \
  apt-get install -y \
    devscripts \
    equivs \
    git \
    m4 \
    make \
    libssl-dev \
    libffi-dev \
    python \
    python-dev \
    python-setuptools && \
  easy_install -U pip

RUN go install -v -race runtime/race

RUN git clone https://bldr-git.int.lineratesystems.com/mirror/gb.git \
  $GOPATH/src/github.com/constabulary/gb && \
  git -C $GOPATH/src/github.com/constabulary/gb checkout 2b9e9134 && \
  go install -v github.com/constabulary/gb/...

COPY k8s-requirements.txt /tmp/k8s-requirements.txt
COPY f5mlb-requirements.txt /tmp/f5mlb-requirements.txt
RUN pip install flake8 && \
  pip install -r /tmp/k8s-requirements.txt && \
  pip install -r /tmp/f5mlb-requirements.txt
#
# Add doc build requirements
#
COPY requirements.docs.txt /tmp/requirements.docs.txt
RUN pip install -r /tmp/requirements.docs.txt

WORKDIR /wkdir
CMD [ "/bin/bash" ]
