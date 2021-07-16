FROM python:3.8-slim

# Labels.

COPY requirements.yml /root/requirements.yml  
RUN python3 -m pip install --upgrade ncclient pyats genie ansible-core boto3 && \
    apt-get update && \
    apt-get install -y git openssh-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    ansible-galaxy collection install cisco.iosxr community.aws amazon.aws ansible.netcommon && \
    ansible-galaxy install -r /root/requirements.yml -p /root/.ansible/roles


CMD [ "ansible-playbook", "--version" ]

