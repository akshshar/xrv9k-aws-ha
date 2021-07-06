FROM centos:8

RUN yum install -y pinentry rpm-sign rpm-build

COPY build_rpm.sh /usr/sbin/
# FROM akshshar/xr-wrl7

# COPY build_rpm.sh /usr/sbin/
