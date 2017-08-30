PACKAGE  := github.com/F5Networks/k8s-bigip-ctlr

BASE     := $(GOPATH)/src/$(PACKAGE)
GOOS     = $(shell go env GOOS)
GOARCH   = $(shell go env GOARCH)
GOBIN    = $(GOPATH)/bin/$(GOOS)-$(GOARCH)

GO_BUILD_FLAGS=-v

# Allow users to pass in BASE_OS build options (alpine or rhel7)
BASE_OS ?= alpine


all: local-build

test: local-go-test local-python-test

prod: prod-build

debug: dbg-unit-test

verify: fmt

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
	git describe --all --long

prod-build: pre-build
	@echo "Building with minimal instrumentation..."
	BASE_OS=$(BASE_OS) $(CURDIR)/build-tools/build-release-artifacts.sh
	BASE_OS=$(BASE_OS) $(CURDIR)/build-tools/build-release-images.sh

dbg-build: pre-build
	@echo "Building with race detection instrumentation..."
	go build -race $(GO_BUILD_OPTS) ./...

dbg-unit-test: dbg-build
	@echo "Running unit tests on 'debug' build..."
	$(CURDIR)/build-tools/dbg-build.sh

fmt:
	@echo "Enforcing code formatting using 'go fmt'..."
	$(CURDIR)/build-tools/fmt.sh

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
		--requirements=python/k8s-runtime-requirements.txt \
		--project-path=$(CURDIR) \

docs/_static/ATTRIBUTIONS.md: flatfile_attributions.json  golang_attributions.json  pip_attributions.json
	./build-tools/attributions-generator.sh \
		node /frontEnd/frontEnd.js $(CURDIR)
	mv ATTRIBUTIONS.md $@

#
# Python unit tests
#
_build/venv.local: python/k8s-build-requirements.txt  python/k8s-runtime-requirements.txt
	[ -d "$@" ] || virtualenv "$@"
	. "$@/bin/activate" && pip install $(foreach f,$^,-r $(f))
	touch "$@"

local-python-test: _build/python.testpass

ifeq ($(GOOS), darwin)
# Python tests depend on inotify, which isn't available on mac
_build/python.testpass:
	@echo "SKIPPING PYTHON TESTS"
	@echo "  Use 'make prod' to run python tests"
	touch $@
else
_build/python.testpass: _build/venv.local $(shell find python -type f)
	@mkdir -p $(@D)
	. $(CURDIR)/_build/venv.local/bin/activate \
	  && flake8 $(CURDIR)/python/
	. $(CURDIR)/_build/venv.local/bin/activate \
	  && cd $(CURDIR)/python \
	  && PYTHONPATH=$$PYTHONPATH:$(CURDIR)/python pytest -slvv
	touch $@
endif

