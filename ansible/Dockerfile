FROM python:3.8-slim

# Labels.

COPY requirements.yml /root/requirements.yml  
RUN python3 -m pip install --upgrade ansible-core boto3 scp && \
    apt-get update && \
    apt-get install -y openssh-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    ansible-galaxy collection install cisco.iosxr community.aws amazon.aws ansible.netcommon

CMD [ "ansible-playbook", "--version" ]

