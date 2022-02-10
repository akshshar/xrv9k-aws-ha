#!/bin/bash
set -x

rtr1_instance_id="i-092b5318d504748cd"
rtr2_instance_id="i-0440aeae55f8166f1"


aws iam create-role --role-name ec2access --assume-role-policy-document file://ec2-role-trust-policy.json
aws iam put-role-policy --role-name ec2access --policy-name EC2-Permissions --policy-document file://ec2-role-access-policy.json
aws iam create-instance-profile --instance-profile-name ec2access-profile
aws iam add-role-to-instance-profile --instance-profile-name ec2access-profile --role-name ec2access
aws ec2 associate-iam-instance-profile --instance-id $rtr1_instance_id --iam-instance-profile Name=ec2access-profile
aws ec2 associate-iam-instance-profile --instance-id $rtr2_instance_id --iam-instance-profile Name=ec2access-profile
aws ec2 describe-iam-instance-profile-associations
