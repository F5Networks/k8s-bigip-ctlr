all:
	@printf "\n\nAvailable targets:\n"
	@printf "  release - build and test without instrumentation\n"
	@printf "  debug   - build and test with debug instrumentation\n"
	@printf "  verify  - apply source verification (i.e. formatting,\n"
	@printf "            licensing)\n"
	@printf "  pkg-deb - build Debian packages for all supported distros\n"
	@printf "  pkg-deb-'distro' - build Debian packages for the specified\n"
	@printf "            distro. (ex: make pkg-deb-wily)\n"
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

# Allow user to pass in gb build options
ifeq ($(CLEAN_BUILD),true)
  GB_BUILD_OPTS=-f -F
else
  GB_BUILD_OPTS=
endif

pre-build:
	${PROJ_DIR}/build-tools/build-start.sh

generate: pre-build
	@echo "Generating source files..."
	gb generate

rel-build: generate
	@echo "Building with minimal instrumentation..."
	gb build $(GB_BUILD_OPTS)

dbg-build: generate
	@echo "Building with race detection instrumentation..."
	gb build -race $(GB_BUILD_OPTS)

rel-unit-test: rel-build
	@echo "Running unit tests on 'release' build..."
	gb test -v $(GB_BUILD_OPTS) \
		-test.benchmem \
		-test.cpuprofile profile.cpu.rel \
		-test.blockprofile profile.block.rel \
		-test.memprofile profile.mem.rel
	@echo "Gathering unit test code coverage for 'release' build..."
	${PROJ_DIR}/build-tools/coverage.sh

dbg-unit-test: dbg-build
	@echo "Running unit tests on 'debug' build..."
	gb test -v $(GB_BUILD_OPTS) \
		-test.benchmem \
		-test.cpuprofile profile.cpu.dbg \
		-test.blockprofile profile.block.dbg \
		-test.memprofile profile.mem.dbg
	@echo "Gathering unit test code coverage for 'debug' build..."
	${PROJ_DIR}/build-tools/coverage.sh

fmt:
	@echo "Enforcing code formatting using 'go fmt'..."
	${PROJ_DIR}/build-tools/fmt.sh

pkg-deb-wily:
	debian/package.sh -C debian wily

# Depend on rules for all supported distros
pkg-deb: pkg-deb-wily

devel-image:
	./build-tools/build-devel-image.sh

# Build docs standalone from this repo
doc-preview:
	./build-tools/run-in-docker.sh make -C docs html
	@echo "To view docs:"
	@echo "open docs/_build/html/README.html"
