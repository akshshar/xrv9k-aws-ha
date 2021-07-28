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


