#!/bin/sh
#
# This script assumes you are in the base directory of the
# project.
#
if [ ! -d "vagrant.d" ]
then
	echo "Script $0 must be run from the project's top directory"
	echo "Current directory is `pwd`"
	exit 1
fi

run-parts -v vagrant.d
if [ $? -ne 0 ]
then
        echo "Failed installing $file"
        exit 1
fi

