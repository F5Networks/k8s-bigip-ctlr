#!/bin/bash

set -e
set -x

rm -rf pkg cmd schemas
mkdir -p cmd pkg
git mv src/k8s-bigip-ctlr cmd/.
git mv src/tools/* pkg/.
rm -rf src/tools
git mv src/* pkg/.
rm -rf src
git mv vendor/src/f5/schemas schemas

git commit -m 'Move source files into new locations

Move all the source files into locations to make a normal go project
./godep-fixup/01-move-source.sh
'

# rename {src => cmd}/k8s-bigip-ctlr/main.go (100%)
# rename {src => cmd}/k8s-bigip-ctlr/main_test.go (100%)
# rename {src => cmd}/k8s-bigip-ctlr/namespaces.go (100%)
# rename {src => cmd}/k8s-bigip-ctlr/pythonDriver.go (100%)
# rename {src => cmd}/k8s-bigip-ctlr/test/pyTest.py (100%)
# rename {src => cmd}/k8s-bigip-ctlr/test/testPyTest.sh (100%)
# rename {src => pkg}/appmanager/appManager.go (100%)
# rename {src => pkg}/appmanager/appManager_test.go (100%)
# rename {src => pkg}/appmanager/eventhandler.go (100%)
# rename {src => pkg}/appmanager/virtualServerConfig.go (100%)
# rename {src => pkg}/appmanager/virtualServerConfig_test.go (100%)
# rename {src => pkg}/openshift/openshiftSDNMgr.go (100%)
# rename {src => pkg}/openshift/openshiftSDNMgr_test.go (100%)
# rename {src/tools => pkg}/pollers/nodePoller.go (100%)
# rename {src/tools => pkg}/pollers/nodePoller_test.go (100%)
# rename {src/tools => pkg}/pollers/pollers.go (100%)
# rename {src => pkg}/test/utils.go (100%)
# rename {src => pkg}/watchmanager/labelwatcher.go (100%)
# rename {src => pkg}/watchmanager/watchManager.go (100%)
# rename {src => pkg}/watchmanager/watchManager_test.go (100%)
# rename {src/tools => pkg}/writer/configWriter.go (100%)
# rename {src/tools => pkg}/writer/configWriter_test.go (100%)
# rename vendor/src/f5/schemas => schemas (100%)
