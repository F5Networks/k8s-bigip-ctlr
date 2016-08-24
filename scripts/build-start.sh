#!/bin/bash

PROJ_DIR=`gb env GB_PROJECT_DIR`
git -C ${PROJ_DIR} status
git -C ${PROJ_DIR} describe --all --long
