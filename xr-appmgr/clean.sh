#!/bin/bash

cwd=`dirname "$(readlink -f "$0")"`

rm -r ${cwd}/build/*
rm -r ${cwd}/RPMS/*
echo "# Artifacts during the build process appear in this directory" > ${cwd}/build/README.md
echo "# RPMS built successfully appear here" > ${cwd}/RPMS/README.md
