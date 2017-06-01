PACKAGE  := f5/vlogger

export GOPATH   := $(CURDIR)/_build/gopath
BASE     := $(GOPATH)/src/$(PACKAGE)
GOOS     = $(shell go env GOOS)
GOARCH   = $(shell go env GOARCH)

GO_BUILD_FLAGS=-v


GOBIN = $(GOPATH)/bin/$(GOOS)-$(GOARCH)

# Generate local package lists
#   replace prefix "_$(dir $(CURDIR)" because that is prepended when GOPATH isn't set
#   Exclude all local vendor, becuase we don't want to explicitly build those
ALL_PKGS      := $(shell go list ./...| sed 's,^_$(CURDIR),$(PACKAGE),' |  grep -v "^$(PACKAGE)/vendor")
TEST_PKGS     := $(shell go list -f '{{ if or .TestGoFiles .XTestGoFiles }}{{ .ImportPath }}{{ end }}' ./... | sed 's,^_$(CURDIR),$(PACKAGE),' |  grep -v "^$(PACKAGE)/vendor")
ALL_COVERAGE  := $(addprefix _build/,$(addsuffix .coverage.out,$(TEST_PKGS)))


#
# Normal build for developers. Just builds source.
#
all: local-build

#
# Run unit tests
#
test: local-go-test

#
# Prod build, with all verification
#
prod: local-build local-go-test coverage

#
# Run tests, and genear
#
coverage: _build/coverage.html

#
# Debug build, with all verification
#
debug: GO_BUILD_FLAGS=-v -race
debug: local-build local-go-test 

#
# Remove all build artifacts
#
clean:
	rm -rf _build
	rm -rf _gopath

info: $(BASE)
	@echo "ALL_PKGS: $(ALL_PKGS)"
	@echo "TEST_PKGS: $(ALL_PKGS)"
	@echo "ALL_COVERAGE: $(ALL_COVERAGE)"


############################################################################
# NOTE:
#   The following targets are supporting targets for the publicly maintained
#   targets above. Publicly maintained targets above are always provided.
############################################################################

$(BASE):
	@mkdir -p $(@D)
	ln -s $(CURDIR) $@

local-build: | $(BASE)
	cd $(BASE) && GOBIN=$(GOBIN) go install $(GO_BUILD_FLAGS) ./... 

# Build isn't required, but makes repeat builds faster
local-go-test: local-build | $(BASE)
	cd $(BASE) && go test $(GO_BUILD_FLAGS) $(TEST_PKGS)

fmt: | $(BASE)
	@git diff --exit-code || {echo "Can't format code with local changes";false;}
	@echo "Files that need formating:"
	@go fmt $(ALL_PKGS)
	@git diff --exit-code


.PHONY: always-build

_build/%.coverage.out: $(BASE) always-build
	@mkdir -p $(@D)
	cd $(BASE) && go test $(GO_BUILD_FLAGS) -covermode=count -coverprofile=$@ $*


_build/coverage.out: $(ALL_COVERAGE) | $(BASE)
	@mkdir -p $(@D)
	cd $(BASE) && gocovmerge $(ALL_COVERAGE) > $@

_build/coverage.html: _build/coverage.out | $(BASE)
	cd $(BASE) && go tool cover -html=$< -o $@
	cd $(BASE) && go tool cover -func=$<
	@cd $(BASE) && go tool cover -func=$< | grep "^total:" | awk 'END { print "Total coverage:", $$3, "of statements" }'


# Disable builtin implicit rules
.SUFFIXES:

