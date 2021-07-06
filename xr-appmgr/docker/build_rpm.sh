#!/bin/bash


usage="
$(basename "$0") [-h] [-s/--spec-file -k/--gpg-key -l/--log-file  -v/--verbose] -- script to initiate an RPM build for WRL7, given a spec file
where:
    -h, --help  show this help text
    -s, --spec-file  Path to spec file for RPM build
    -k, --gpg-key  Path to gpg key for RPM build
    -r, --source-dir  Path to rpm SOURCES dir
    -p, --rpm-dir  Path to RPMS dir 
    -o, --output-dir  Path to location to place built RPMS
    -l, --log-file  Path to log file for build process (Default:  /tmp/rpmbuild.log)
    -v, --verbose  get more verbose information during script execution
"

while true; do
  case "$1" in
    -v | --verbose )         VERBOSE=true; shift ;;
    -h | --help )            echo "$usage"; exit 0 ;;
    -s | --spec-file )       spec_file=$2;shift; shift;; 
    -k | --gpg-key )         gpg_key=$2;shift; shift;;
    -r | --source-dir )      source_dir=$2;shift; shift;;
    -p | --rpm-dir )         rpm_dir=$2;shift; shift;;
    -o | --output-dir )      output_dir=$2;shift; shift;;
    -l | --log-file )        log_file=$2; shift; shift;;
    -- ) shift; break ;;
    * ) break;;
  esac
done

if [[ $VERBOSE ]];then
    set -x
fi

if [[ $log_file == "" ]]; then
    log_file="/tmp/rpmbuild.log"
fi

if [[ $spec_file == "" ]]; then
    echo "No spec file specified for RPM build, bailing out"
    exit 1
fi

if [[ $source_dir == "" ]]; then
    echo "No SOURCES dir specified for RPM build, bailing out"
    exit 1
fi

if [[ $rpm_dir == "" ]]; then
    echo "No RPMS dir specified for RPM build, bailing out"
    exit 1
fi

if [[ $output_dir == "" ]]; then
    echo "No output dir specified for RPM build, bailing out"
    exit 1
fi

mkdir -p $output_dir
chown -Rf root:root $output_dir
chown -Rf root:root $source_dir/*
chown -Rf root:root $(dirname $spec_file)/*

if [[ $gpg_key != "" ]]; then
    gpg --allow-secret-key-import --import "${gpg_key}" > ${log_file} 2>&1
    # FIXME: This doesn't work so hardcoding for now
    gpg_name=$(gpg --list-secret-keys | grep uid | awk '{{ print $4 }}')
    cat << __EOF__ > ~/.rpmmacros
%_gpg_name appmgr-test
%_gpg /usr/bin/gpg
%_gpg_path /root/.gnupg
__EOF__
    echo "GPG key specified. Attempting to import key"
fi

/usr/bin/rpmbuild --verbose -bb ${spec_file} > ${log_file} 2>&1
rpm_build_ec=$?

if [[ $rpm_build_ec -eq 0 ]]; then
    echo "RPM built successfully, copying over the RPMs directory to /root/RPMS"
else
    echo "Failed to build RPM. Check logfile $logfile for errors"
    exit 1
fi

if [[ $gpg_key != "" ]]; then
    echo "GPG key specified. Attempting to sign rpm"
    find $rpm_dir -name "*.rpm" -exec rpm --addsign {} \;
fi

cp -r $rpm_dir/* $output_dir

sync

ls -R $output_dir

