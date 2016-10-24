all:
	@printf "\n\nAvailable targets:\n"
	@printf "  release - build and test without instrumentation\n"
	@printf "  debug   - build and test with debug instrumentation\n"
	@printf "  verify  - apply source verification (i.e. formatting,\n"
	@printf "            licensing)\n"
	@printf "  pkg-deb - build Debian packages for all supported distros\n"
	@printf "  pkg-deb-'distro' - build Debian packages for the specified\n"
	@printf "            distro. (ex: make pkg-deb-wily)\n"
	@printf "  build-deps - install build dependencies\n"
	@printf "  devel-image - build a local docker image 'k8s-ctrl-devel'\n"
	@printf "                with all needed build tools\n"
	@printf "  doc-preview - Use devel image to build local preview of docs\n"

release: pre-build generate rel-build rel-unit-test

debug: pre-build generate dbg-build dbg-unit-test

verify: pre-build fmt

############################################################################
# NOTE:
#   The following targets are supporting targets for the publicly maintained
#   targets above. Publicly maintained targets above are always provided.
############################################################################

# Use GB to get the project's directory.
PROJ_DIR = $(shell gb env GB_PROJECT_DIR)

pre-build:
	${PROJ_DIR}/scripts/build-start.sh

generate: pre-build
	@echo "Generating source files..."
	gb generate

rel-build: generate
	@echo "Building with minimal instrumentation..."
	gb build

dbg-build: generate
	@echo "Building with race detection instrumentation..."
	gb build -race

rel-unit-test: rel-build
	@echo "Running unit tests on 'release' build..."
	gb test -v \
		-test.benchmem \
		-test.cpuprofile profile.cpu.rel \
		-test.blockprofile profile.block.rel \
		-test.memprofile profile.mem.rel
	@echo "Gathering unit test code coverage for 'release' build..."
	${PROJ_DIR}/scripts/coverage.sh

dbg-unit-test: dbg-build
	@echo "Running unit tests on 'debug' build..."
	gb test -v \
		-test.benchmem \
		-test.cpuprofile profile.cpu.dbg \
		-test.blockprofile profile.block.dbg \
		-test.memprofile profile.mem.dbg
	@echo "Gathering unit test code coverage for 'debug' build..."
	${PROJ_DIR}/scripts/coverage.sh

fmt:
	@echo "Enforcing code formatting using 'go fmt'..."
	${PROJ_DIR}/scripts/fmt.sh

pkg-deb-wily:
	debian/package.sh -C debian wily

# Depend on rules for all supported distros
pkg-deb: pkg-deb-wily

build-deps:
	@echo "Installing build dependencies"
	@VAGRANT_INSTALL=${VAGRANT_INSTALL} ./scripts/build-deps.sh

devel-image:
	cp requirements.docs.txt scripts/devel-image/
	cd scripts/devel-image && docker build -t f5-k8s-ctrl-devel .

doc-preview: doc-preview-standalone doc-preview-combined

# Build docs standalone from this repo
doc-preview-standalone:
	./scripts/run-in-docker.sh make -C docs html
	@echo "To view docs:"
	@echo "open docs/_build/html/README.html"

# Build docs from the top-level repo (github.com/f5-ci-docs)
doc-preview-combined:
	[ -d f5-ci-docs ] || git clone -b gitlab-ci git@github.com:F5Networks/f5-ci-docs.git
	./scripts/merge-docs.sh f5-ci-docs
	./scripts/run-in-docker.sh make -C f5-ci-docs/docs html
	@echo "To view docs:"
	@echo "open f5-ci-docs/docs/_build/html/index.html"
