PACKAGE  := github.com/F5Networks/k8s-bigip-ctlr

BASE     := $(GOPATH)/src/$(PACKAGE)
GOOS     = $(shell go env GOOS)
GOARCH   = $(shell go env GOARCH)
GOBIN    = $(GOPATH)/bin/$(GOOS)-$(GOARCH)

NEXT_VERSION := $(shell ./build-tools/version-tool version)
export BUILD_VERSION := $(if $(BUILD_VERSION),$(BUILD_VERSION),$(NEXT_VERSION))
export BUILD_INFO := $(shell ./build-tools/version-tool build-info)

GO_BUILD_FLAGS=-v -ldflags "-extldflags \"-static\" -X main.version=$(BUILD_VERSION) -X main.buildInfo=$(BUILD_INFO)"

# Allow users to pass in BASE_OS build options (alpine or rhel7)
BASE_OS ?= alpine

# This is for builds not triggered through Travis CI 
LICENSE_STRICT ?= false

# If strict license approval check is desired, pass the corresponding flag 
# to Attributions Generator on command line
ifeq ($(LICENSE_STRICT), true)
	LIC_FLAG=--al release
endif

all: local-build

test: local-go-test

prod: prod-build

debug: dbg-build

verify: fmt vet

docs: _docs


godep-restore: check-gopath
	godep restore
	rm -rf vendor Godeps

godep-save: check-gopath
	godep save ./...

clean:
	rm -rf _docker_workspace
	rm -rf _build
	rm -rf docs/_build
	rm -f *_attributions.json
	rm -f docs/_static/ATTRIBUTIONS.md
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

local-go-test: local-build check-gopath
	ginkgo ./pkg/... ./cmd/...

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
	@echo "Building with minimal instrumentation..."
	BASE_OS=$(BASE_OS) $(CURDIR)/build-tools/build-devel-image.sh
	RUN_TESTS=1 BASE_OS=$(BASE_OS) $(CURDIR)/build-tools/build-release-artifacts.sh
	BASE_OS=$(BASE_OS) $(CURDIR)/build-tools/build-release-images.sh

prod-quick: prod-build-quick

prod-build-quick: pre-build
	@echo "Building with running tests..."
	BASE_OS=$(BASE_OS) $(CURDIR)/build-tools/build-devel-image.sh
	RUN_TESTS=0 BASE_OS=$(BASE_OS) $(CURDIR)/build-tools/build-release-artifacts.sh
	BASE_OS=$(BASE_OS) $(CURDIR)/build-tools/build-release-images.sh

dbg-build: pre-build
	@echo "Building with race detection instrumentation..."
	BASE_OS=$(BASE_OS) $(CURDIR)/build-tools/build-debug-artifacts.sh

fmt:
	@echo "Enforcing code formatting using 'go fmt'..."
	$(CURDIR)/build-tools/fmt.sh

vet:
	@echo "Running 'go vet'..."
	$(CURDIR)/build-tools/vet.sh

devel-image:
	BASE_OS=$(BASE_OS) ./build-tools/build-devel-image.sh

#
# Docs
#
doc-preview:
	rm -rf docs/_build
	DOCKER_RUN_ARGS="-p 127.0.0.1:8000:8000" \
	  ./build-tools/docker-docs.sh make -C docs preview

_docs: docs/_static/ATTRIBUTIONS.md always-build
	./build-tools/docker-docs.sh ./build-tools/make-docs.sh

docker-test:
	rm -rf docs/_build
	./build-tools/docker-docs.sh ./build-tools/make-docs.sh

# one-time html build using a docker container
.PHONY: docker-html
docker-html:
	rm -rf docs/_build
	./build-tools/docker-docs.sh make -C docs/ html

#
# Attributions Generation
#
golang_attributions.json: Godeps/Godeps.json
	./build-tools/attributions-generator.sh \
		/usr/local/bin/golang-backend.py --project-path=$(CURDIR)

flatfile_attributions.json: .f5license
	./build-tools/attributions-generator.sh \
		/usr/local/bin/flatfile-backend.py --project-path=$(CURDIR)

pip_attributions.json: always-build
	./build-tools/attributions-generator.sh \
		/usr/local/bin/pip-backend.py \
		--requirements=requirements.txt \
		--project-path=$(CURDIR) \

docs/_static/ATTRIBUTIONS.md: flatfile_attributions.json  golang_attributions.json  pip_attributions.json
	./build-tools/attributions-generator.sh \
		node /frontEnd/frontEnd.js --pd $(CURDIR) $(LIC_FLAG)
	mv ATTRIBUTIONS.md $@
