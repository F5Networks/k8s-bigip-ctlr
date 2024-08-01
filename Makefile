PACKAGE  := github.com/F5Networks/k8s-bigip-ctlr

BASE     := $(GOPATH)/src/$(PACKAGE)
GOOS     = $(shell go env GOOS)
GOARCH   = $(shell go env GOARCH)
GOBIN    = $(GOPATH)/bin/$(GOOS)-$(GOARCH)

NEXT_VERSION := $(shell ./build-tools/version-tool version)
export BUILD_VERSION := $(if $(BUILD_VERSION),$(BUILD_VERSION),$(NEXT_VERSION))
export BUILD_INFO := $(shell ./build-tools/version-tool build-info)

GO_BUILD_FLAGS=-v -ldflags "-extldflags \"-static\" -X main.version=$(BUILD_VERSION) -X main.buildInfo=$(BUILD_INFO)"

# Allow users to pass in BASE_OS build options (debian or rhel7)
BASE_OS ?= debian

# This is for builds not triggered through Travis CI 
LICENSE_STRICT ?= false

# If strict license approval check is desired, pass the corresponding flag 
# to Attributions Generator on command line
ifeq ($(LICENSE_STRICT), true)
	LIC_FLAG=--al release
endif

all: local-build

test: local-go-test

coverage: local-go-coverage

create-coverage-report: create-coverage-report

prod: prod-build

verify: fmt vet

docs: _docs

clean:
	rm -rf _docker_workspace
	rm -rf _build
	docker volume rm -f workspace_vol
	@echo "Did not clean local go workspace"

info:
	env


############################################################################
# NOTE:
#   The following targets are supporting targets for the publicly maintained
#   targets above. Publicly maintained targets above are always provided.
############################################################################

# Depend on always-build when inputs aren't known
.PHONY: always-build

# Disable builtin implicit rules
.SUFFIXES:

local-go-coverage:
	go install github.com/Azure/gocover@latest
	$(GOPATH)/bin/gocover test --repository-path=. --coverage-mode full --executor-mode go --excludes "**/config/**,**/vlogger/**,**/test/**,**/prometheus/**,**/mockmanager/**" --outputdir ./
	awk "!/\/config\/|vlogger|prometheus|mockmanager|\/test\/test/" coverage.out >coverage-new.out
	mv coverage-new.out coverage.out
	grep "Coverage (with ignorance)" coverage.html | head -1 | awk 'END { print "Total coverage:", $$4, "of statements" }'
	#go tool cover -func=coverage.out | grep "^total:" | awk 'END { print "Total coverage:", $$3, "of statements" }'
	@if [ $(COVERALLS_TOKEN) ]; then \
		go install github.com/mattn/goveralls@latest; \
		echo "Pushing coverage data to coveralls"; \
		$(GOPATH)/bin/goveralls -coverprofile=./coverage.out -service=azure; \
	fi

local-go-test:
	go install github.com/onsi/ginkgo/v2/ginkgo
	go install github.com/onsi/gomega
	$(GOPATH)/bin/ginkgo -r --procs=4 --compilers=1 --randomize-all --randomize-suites --fail-on-pending --keep-going --trace --junit-report=report.xml --timeout=300s --flake-attempts=3 --succinct

create-coverage-report: local-go-coverage
	go install github.com/axw/gocov/gocov@latest
	go install github.com/AlekSi/gocov-xml@latest
	$(GOPATH)/bin/gocov convert coverage.out > coverage.json
	$(GOPATH)/bin/gocov-xml < coverage.json > coverage.xml

local-build: check-gopath
	GOBIN=$(GOBIN) go install $(GO_BUILD_FLAGS) ./pkg/... ./cmd/...

check-gopath:
	@if [ "$(BASE)" != "$(CURDIR)" ]; then \
	  echo "Source directory must be in valid GO workspace."; \
	  echo "Check GOPATH?"; \
	  false; \
	fi

pre-build:
	git status
	git describe --all --long --always

prod-build: pre-build
	@echo "Building with running tests..."

	docker build --platform linux/amd64 --build-arg RUN_TESTS=1 --build-arg BUILD_VERSION=$(BUILD_VERSION) --build-arg BUILD_INFO=$(BUILD_INFO) -t k8s-bigip-ctlr:latest -f build-tools/Dockerfile.$(BASE_OS) .

prod-quick: prod-build-quick

prod-build-quick: pre-build
	@echo "Quick build without running tests..."
	docker build --platform linux/amd64 --build-arg RUN_TESTS=0 --build-arg BUILD_VERSION=$(BUILD_VERSION) --build-arg BUILD_INFO=$(BUILD_INFO) -t k8s-bigip-ctlr:latest -f build-tools/Dockerfile.$(BASE_OS) .

dev-license: pre-build
	@echo "Running with tests and licenses generated will be in all_attributions.txt..."
	docker build -t cis-attributions:latest -f build-tools/Dockerfile.attribution .
	$(eval id := $(shell docker create cis-attributions:latest))
	docker cp $(id):/opt/all_attributions.txt ./
	docker rm -v $(id)
	docker rmi -f cis-attributions:latest

debug: pre-build
	@echo "Building with debug support..."
	docker build --platform linux/amd64 --build-arg RUN_TESTS=0 --build-arg BUILD_VERSION=$(BUILD_VERSION) --build-arg BUILD_INFO=$(BUILD_INFO) -t k8s-bigip-ctlr-dbg:latest -f build-tools/Dockerfile.debug .


fmt:
	@echo "Enforcing code formatting using 'go fmt'..."
	$(CURDIR)/build-tools/fmt.sh

vet:
	@echo "Running 'go vet'..."
	$(CURDIR)/build-tools/vet.sh

devel-image:
	docker build --platform linux/amd64 --build-arg RUN_TESTS=0 --build-arg BUILD_VERSION=$(BUILD_VERSION) --build-arg BUILD_INFO=$(BUILD_INFO) -t k8s-bigip-ctlr-devel:latest -f build-tools/Dockerfile.$(BASE_OS) .

# Enable certain funtionalities only on a developer build
dev-patch:
	git apply --check build-tools/golang/0001-Enable-AS3-Declaration-logging.patch
	git apply build-tools/golang/0001-Enable-AS3-Declaration-logging.patch

reset-dev-patch:
	git apply -R $(CURDIR)/build-tools/golang/0001-Enable-AS3-Declaration-logging.patch

# Build devloper image
dev: dev-patch prod-quick reset-dev-patch

# Docs
doc-preview:
	rm -rf docs/_build
	DOCKER_RUN_ARGS="-p 127.0.0.1:8000:8000" \
	  ./build-tools/docker-docs.sh make -C docs preview

_docs: always-build
	./build-tools/docker-docs.sh ./build-tools/make-docs.sh

docker-test:
	rm -rf docs/_build
	./build-tools/docker-docs.sh ./build-tools/make-docs.sh

docker-tag:
ifdef tag
	docker tag k8s-bigip-ctlr:latest $(tag)
	docker push $(tag)
else
	@echo "Define a tag to push. Eg: make docker-tag tag=username/k8s-bigip-ctlr:dev"
endif

docker-devel-tag:
	docker push k8s-bigip-ctlr-devel:latest

docker-dbg-tag:
ifdef tag
	docker tag k8s-bigip-ctlr-dbg:latest $(tag)
	docker push $(tag)
else
	@echo "Define a tag to push. Eg: make docker-tag tag=username/k8s-bigip-ctlr:dev"
endif

crd-code-gen:
	docker run --platform linux/amd64 --name crdcodegen -v $(PWD):/go/src/github.com/F5Networks/k8s-bigip-ctlr/v3 quay.io/f5networks/ciscrdcodegen:v1
	docker rm crdcodegen