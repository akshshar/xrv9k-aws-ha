#!/bin/bash
set -x
SECONDS=0
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'
echo "####################################################"
echo -e "${GREEN}Bringing up the xrv9k HA topology on AWS ...${NC}"
echo "####################################################"


# Init Terraform to run against AWS EC2 before starting the build
docker run -it --rm --name ami_builder -v ${PWD}/ssh:/root/ssh \
           -v ${PWD}/aws:/root/.aws \
           -v ${PWD}/ssh_config:/root/.ssh/config  \
           -v ${PWD}/playbooks:/root/playbooks \
           -v ${PWD}/ansible.cfg:/root/playbooks/ansible.cfg \
           -w /root/playbooks \
           ansible_client:latest \
           /bin/bash -c "ansible-playbook -vvv /root/playbooks/unprovision.yml --private-key /root/ssh/id_rsa"

if [ $? -ne 0 ]; then
   echo -e "${RED}Failed to run provisioning playbook, exiting...${NC}"
   duration=$SECONDS
   echo "$(($duration / 60)) mins $(($duration % 60)) seconds elapsed."
   exit 1
fi
