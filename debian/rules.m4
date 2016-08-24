#!/usr/bin/make -f
# -*- makefile -*-

# Uncomment for verbose mode
#DH_VERBOSE = 1

%:
	dh $@ --buildsystem=makefile --parallel

# Need to override dh_auto_build to pass correct parameters to make
override_dh_auto_build:
	$(MAKE) `'m4_BUILD_TYPE`'

