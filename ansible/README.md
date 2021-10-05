The Ansible playbook is set up to launch a cloudformation topology in AWS with hardcoded private IPs.
View the cloudformation template: `/ansible/cloudformation/xrv9k_aws_ha_topo_basic.yml` from the root of the git repository

## Cloudformation Topology
The topology launched by the Ansible playbook + Cloudformation template is shown below:

![](/images/xrv9k_ha_ansible_cf_topo.png)

This topology includes a VPC endpoint to enable private access to EC2 API services. Further, the IAM role and policy to allow access to the EC2 API (via temporary security credentials) is automatically set up in the cloudformation template as well.

Effectively, this topology can be simplified to:

![](/images/simplified_ansible_cf_topo.png)


## Requirements: Setting up the Client Machine (Laptop/Server)

### Set up Routing to AWS

The client machine may be your laptop or any server/machine thas has internet access capable of reaching AWS public ip addresses.
You can view the block of public IP addresses that AWS uses by navigating here:  <https://ip-ranges.amazonaws.com/ip-ranges.json> and setting up routing appropriately.


### Compatible OS

Technically the entire spin-up process runs using docker containers and nothing needs to be installed on the client machine except for docker itself. Since docker is supported on Linux, MacOSX and Windows, you should be able to run the build code on any of these operating systems once docker is up and running.

### Install Docker Engine

Navigate here: <https://docs.docker.com/engine/install/> to install Docker Engine for the OS running on your selected Client Machine. The instructions below capture the build flow from MacOSX.


### Fetch your AWS Credentials
You will need to set up your AWS credentials before running the code. So fetch your Access Key and Secret Key as described here for programmatic access to AWS APIs:
<https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys>  
and keep them ready.




## Working with xrv9k-aws-ha Ansible+CloudFormation

### Clone the git repo

```
aks::~$git clone https://github.com/akshshar/xrv9k-aws-ha
Cloning into 'xrv9k-aws-ha'...

```


### Set up the AWS credentials

As explained in the requirements section, once you have the Access Key and Secret Key associated with your account ready, fill out `/ansible/aws/credentials` file in the git repo:

```
aks::~/xrv9k-aws-ha$  cat ansible/aws/credentials 
[default]
aws_access_key_id =
aws_secret_access_key =

```

### Copy rsa key pair of your Client Machine to ssh/

Generate an RSA key pair:
private-key filename:  id_rsa 
public-key filename: id_rsa.pub

Follow the instructions relevant to the OS of your client machine to do so.
Then copy the key files over to the `/ansible/ssh/` directory of the cloned git repo:

```
aks::~/xrv9k-aws-ha$ cd ansible/
aks::~/xrv9k-aws-ha/ansible$cp ~/.ssh/id_rsa* ssh/
aks::~/xrv9k-aws-ha/ansible$
aks::~/xrv9k-aws-ha/ansible$tree ./ssh
./ssh
├── PlaceSSHKeysHere.md
├── id_rsa
└── id_rsa.pub

0 directories, 3 files
aks::~/xrv9k-aws-ha/ansible$
```

## Build the Ansible Docker image

```
aks::~/xrv9k-aws-ha/ansible$ docker build -t ansible_client .
[+] Building 226.2s (8/8) FINISHED                                                                                                                                                                    
 => [internal] load build definition from Dockerfile                                                                                                                                             0.0s
 => => transferring dockerfile: 451B                                                                                                                                                             0.0s
 => [internal] load .dockerignore                                                                                                                                                                0.0s
 => => transferring context: 2B                                                                                                                                                                  0.0s
 => [internal] load metadata for docker.io/library/python:3.8-slim                                                                                                                               5.5s
 => [internal] load build context                                                                                                                                                                0.0s
 => => transferring context: 128B                                                                                                                                                                0.0s
 => [1/3] FROM docker.io/library/python:3.8-slim@sha256:47bcfecfc8b486a6cbd86cf2c67d74a18519ed29d43b5d4ee20692433e81d0a1                                                                        84.5s
 => => resolve docker.io/library/python:3.8-slim@sha256:47bcfecfc8b486a6cbd86cf2c67d74a18519ed29d43b5d4ee20692433e81d0a1                                                                         0.0s
 => => sha256:6d9f6b5c1e712fa60caf3b1b4644b47abe0bec3fd2b6389bc1f8114f3269b9a9 10.76MB / 10.76MB                                                                                                42.2s
 => => sha256:47bcfecfc8b486a6cbd86cf2c67d74a18519ed29d43b5d4ee20692433e81d0a1 1.86kB / 1.86kB                                                                                                   0.0s
 => => sha256:00d7c12a2ae7d176a855da66e81184eaa63aedc96083547a80a219f681f4c228 1.37kB / 1.37kB                                                                                                   0.0s
 => => sha256:2e56f6b0af6977ccaf1680c9e464aa85d83925e06130ede28a6f755fde312282 7.92kB / 7.92kB                                                                                                   0.0s
 => => sha256:bd897bb914af2ec64f1cff5856aefa1ae99b072e38db0b7d801f9679b04aad74 31.37MB / 31.37MB                                                                                                81.8s
 => => sha256:aee78d8222132bc168ae0d97914077508c31763bb168955723883c59593868ae 1.08MB / 1.08MB                                                                                                   3.3s
 => => sha256:cf9f290bd6be1670494fceedbf07a21958f8e99ef25ca48f1291410c7544a6b5 233B / 233B                                                                                                       4.4s
 => => sha256:5e4b501cbda59bcec36db68e2b95f750a8499c7d0d8cc274e12c858379570ecb 2.64MB / 2.64MB                                                                                                   9.1s
 => => extracting sha256:bd897bb914af2ec64f1cff5856aefa1ae99b072e38db0b7d801f9679b04aad74                                                                                                        1.4s
 => => extracting sha256:aee78d8222132bc168ae0d97914077508c31763bb168955723883c59593868ae                                                                                                        0.1s
 => => extracting sha256:6d9f6b5c1e712fa60caf3b1b4644b47abe0bec3fd2b6389bc1f8114f3269b9a9                                                                                                        0.5s
 => => extracting sha256:cf9f290bd6be1670494fceedbf07a21958f8e99ef25ca48f1291410c7544a6b5                                                                                                        0.0s
 => => extracting sha256:5e4b501cbda59bcec36db68e2b95f750a8499c7d0d8cc274e12c858379570ecb                                                                                                        0.2s
 => [2/3] COPY requirements.yml /root/requirements.yml                                                                                                                                           0.0s
 => [3/3] RUN python3 -m pip install --upgrade ansible-core boto3 scp &&     apt-get update &&     apt-get install -y openssh-client &&     apt-get clean &&     rm -rf /var/lib/apt/lists/*   134.6s
 => exporting to image                                                                                                                                                                           1.5s 
 => => exporting layers                                                                                                                                                                          1.5s 
 => => writing image sha256:b639e1250482aa72ea1b41a9e1a67201c9c165c3c462005cdf5ca66fcf788340                                                                                                     0.0s 
 => => naming to docker.io/library/ansible_client                                                                                                                                                0.0s 
                                                                                                                                                                                                      
Use 'docker scan' to run Snyk tests against images to find vulnerabilities and learn how to fix them                                                                                                  
aks::~/xrv9k-aws-ha/ansible$

```

## Bring up the 2 node-topology
The Ansible playbook will launch the AWS topology, build the xrv9k HA App RPM and deploy the app with the required config file on the two routers.

To bring up the topo and deploy the app:

```
aks::~/xrv9k-aws-ha/ansible$ ./bringup_stack.sh 

```

## Bring down the topology

```
aks::~/xrv9k-aws-ha/ansible$ ./bringdown_stack.sh 
```


