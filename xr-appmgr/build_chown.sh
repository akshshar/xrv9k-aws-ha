#!/bin/bash

chown -R $1:$2 /root/cwd/RPMS
chown -R $1:$2 /root/cwd/*.spec
chown -R $1:$2 /root/cwd/build
