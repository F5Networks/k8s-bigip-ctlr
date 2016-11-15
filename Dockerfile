FROM golang:1.6

ENV APPPATH /app

RUN mkdir -p "$APPPATH" && chmod -R 777 "$APPPATH"
WORKDIR $APPPATH

COPY . $APPPATH

# Install dependencies, build, and remove the dependencies.
RUN apt-get update -y && \
    apt-get install -y git python python-dev python-pip && \
    PYINOTIFY=$(grep pyinotify python/requirements.txt); \
    pip install $PYINOTIFY && \
    pip install -r vendor/src/velcro/f5-marathon-lb/requirements.txt && \
    go get github.com/constabulary/gb/... && \
    go install github.com/constabulary/gb && \
    gb build -f && \
    (cd python; cp --remove-destination $(readlink _f5.py) _f5.py) && \
    (cd python; cp --remove-destination $(readlink common.py) common.py) && \
    find . -not -name "*bin*" -not -name "*f5-k8s-controller" -not -name ".." -not -name "." -not -path "*python*" | xargs rm -rf && \
    rm -rf $GOPATH/* && \
    apt-get remove -y git python-dev python-pip && \
    apt-get autoremove -y && \
    apt-get clean -y

# Copy over schemas
COPY vendor/src/velcro/schemas/bigip-virtual-server_v*.json $APPPATH/vendor/src/velcro/schemas/

# Run the run application in the projects bin directory.
CMD [ "/app/bin/f5-k8s-controller" ]
