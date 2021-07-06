# xrv9k_ha
Onbox docker App to enable High-Availability for XRv9k on AWS using IOS-XR Service-Layer API and AWS API

## How does it work?

Check out the solution guide: [HA_redundancy_xrv9k_soln.pdf](/HA_redundancy_xrv9k_soln.pdf) for details on how the application works.
The figures below capture the design details:

![](/images/ha_app_solution_design.png)

![](/images/ha_app_solution_design_secondary_ip.png)


## Build App


### Build the Docker image (or Download pre-built latest version)

**Note**: Make sure Docker is installed on your build server/laptop - instructions [here](https://docs.docker.com/engine/install/).

```
aks::~/ha_app_xrv9k$
aks::~/ha_app_xrv9k$cd core/python/
aks::~/ha_app_xrv9k/core/python$
aks::~/ha_app_xrv9k/core/python$docker build -t akshshar/xrv9k_aws_ha .
Sending build context to Docker daemon  1.477MB
Step 1/17 : FROM python:3.8-slim as builder
 ---> b298bacb2734
Step 2/17 : RUN apt-get update &&     apt-get install -y gcc &&     apt-get clean
 ---> Using cache
 ---> 66c9e6285ad9
Step 3/17 : COPY src/app /app
 ---> ca311a236235
Step 4/17 : WORKDIR app
 ---> Running in a455c337f656
Removing intermediate container a455c337f656
 ---> 3b1663658191
Step 5/17 : RUN python3 -m pip install --user -r requirements.txt
 ---> Running in c12edaaca0a7
Collecting rdbtools
  Downloading rdbtools-0.1.15.tar.gz (31 kB)
Collecting python-lzf
  Downloading python-lzf-0.2.4.tar.gz (9.3 kB)
Collecting grpcio
  Downloading grpcio-1.38.1-cp38-cp38-manylinux2014_x86_64.whl (4.2 MB)
Collecting grpcio-tools
  Downloading grpcio_tools-1.38.1-cp38-cp38-manylinux2014_x86_64.whl (2.5 MB)
Collecting boto3
  Downloading boto3-1.17.105-py2


  ..........




  Removing intermediate container d2f69f2f2d5d
 ---> 91195bbe9542
Step 17/17 : CMD ["/usr/local/bin/python3", "/root/.local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]
 ---> Running in 8459c24eceb9
Removing intermediate container 8459c24eceb9
 ---> c23601535cd8
Successfully built c23601535cd8
Successfully tagged akshshar/xrv9k_aws_ha:latest
aks::~/ha_app_xrv9k/core/python$
aks::~/ha_app_xrv9k/core/python$

```

The Docker image should appear in the local docker registry:

```
aks::~/ha_app_xrv9k/core/python$docker images akshshar/xrv9k_aws_ha
REPOSITORY              TAG                 IMAGE ID            CREATED              SIZE
akshshar/xrv9k_aws_ha   latest              c23601535cd8        About a minute ago   309MB
aks::~/ha_app_xrv9k/core/python$

```


**Note**: If you'd like to download a pre-built docker image from dockerhub, just issue a docker pull:

```
aks::~$
aks::~$docker pull akshshar/xrv9k-aws-ha:latest
latest: Pulling from akshshar/xrv9k-aws-ha
000eee12ec04: Already exists 
ddc2d83f8229: Already exists 
3ae1660fa0d9: Already exists 
ef709117d3d3: Already exists 
487a0421e8fa: Already exists 
199045e43db5: Downloading [===========================>                       ]  10.27MB/18.37MB
5f1db3d1ff14: Download complete 
8ee41ff6fca0: Downloading [===========================>                       ]  8.932MB/16.32MB
d7376ff144fe: Download complete 
1a2a1997dd86: Downloading [>                                  

```



### Build the Application RPM from docker image for deployment


Drop into the app specific folder under `/xr-appmgr/` in the root of the cloned git repository

```
ks::~/ha_app_xrv9k$
aks::~/ha_app_xrv9k$
aks::~/ha_app_xrv9k$cd xr-appmgr/src/apps/xrv9k_aws_ha/
aks::~/ha_app_xrv9k/xr-appmgr/src/apps/xrv9k_aws_ha$
aks::~/ha_app_xrv9k/xr-appmgr/src/apps/xrv9k_aws_ha$ docker save akshshar/xrv9k-aws-ha:latest > xrv9k_aws_ha.tar
aks::~/ha_app_xrv9k/xr-appmgr/src/apps/xrv9k_aws_ha$
aks::~/ha_app_xrv9k/xr-appmgr/src/apps/xrv9k_aws_ha$

```

From the `/xr-appmgr/` folder, issue a build for xr-appmgr compatible RPM build:

```
aks::~/ha_app_xrv9k$cd xr-appmgr/
aks::~/ha_app_xrv9k/xr-appmgr$
aks::~/ha_app_xrv9k/xr-appmgr$
aks::~/ha_app_xrv9k/xr-appmgr$  ./appmgr_build -b build.yaml 
Starting to build package: xrv9k-aws-ha
Building docker image arhashem/xr-wrl7...
docker build docker -f docker/WRL7.Dockerfile -t arhashem/xr-wrl7
Sending build context to Docker daemon  6.656kB
Step 1/2 : FROM akshshar/xr-wrl7
 ---> a25bec9d92f6
Step 2/2 : COPY build_rpm.sh /usr/sbin/
 ---> Using cache
 ---> 04f3d0717d48
Successfully built 04f3d0717d48
Successfully tagged arhashem/xr-wrl7:latest
Adding sources...
 ---> xrv9k_aws_ha
Adding configs...
 ---> xrv9k_aws_ha
Adding data...
Creating source archive...
Generating spec file: xrv9k-aws-ha-0.1.0-eXR.spec
Building RPM...
/usr/sbin/build_rpm.sh --spec-file /usr/src/rpm/SPECS/xrv9k-aws-ha-0.1.0-eXR.spec --source-dir /usr/src/rpm/SOURCES --rpm-dir /usr/src/rpm/RPMS --output-dir /root/RPMS --verbose
+ [[ '' == '' ]]
+ log_file=/tmp/rpmbuild.log
+ [[ /usr/src/rpm/SPECS/xrv9k-aws-ha-0.1.0-eXR.spec == '' ]]
+ [[ /usr/src/rpm/SOURCES == '' ]]
+ [[ /usr/src/rpm/RPMS == '' ]]
+ [[ /root/RPMS == '' ]]
+ mkdir -p /root/RPMS
+ chown -Rf root:root /root/RPMS
+ chown -Rf root:root /usr/src/rpm/SOURCES/xrv9k-aws-ha-0.1.0-eXR.tar.gz
++ dirname /usr/src/rpm/SPECS/xrv9k-aws-ha-0.1.0-eXR.spec
+ chown -Rf root:root /usr/src/rpm/SPECS/xrv9k-aws-ha-0.1.0-eXR.spec
+ [[ '' != '' ]]
+ /usr/bin/rpmbuild --verbose -bb /usr/src/rpm/SPECS/xrv9k-aws-ha-0.1.0-eXR.spec
+ rpm_build_ec=0
+ [[ 0 -eq 0 ]]
+ echo 'RPM built successfully, copying over the RPMs directory to /root/RPMS'
RPM built successfully, copying over the RPMs directory to /root/RPMS
+ [[ '' != '' ]]
+ cp -r /usr/src/rpm/RPMS/noarch /usr/src/rpm/RPMS/x86_64 /root/RPMS
+ sync
+ ls -R /root/RPMS
/root/RPMS:
noarch	x86_64

/root/RPMS/noarch:

/root/RPMS/x86_64:
xrv9k-aws-ha-0.1.0-eXR.x86_64.rpm

Done building package xrv9k-aws-ha

aks::~/ha_app_xrv9k/xr-appmgr$
aks::~/ha_app_xrv9k/xr-appmgr$
aks::~/ha_app_xrv9k/xr-appmgr$ ls -l RPMS/x86_64/
total 202112
-rw-r--r--  1 akshshar  staff  95900546 Jul  6 18:07 xrv9k-aws-ha-0.1.0-eXR.x86_64.rpm
aks::~/ha_app_xrv9k/xr-appmgr$

```


### Create config.json for each router based on the router configurations

Sample configuration files are present under `/core/python/src/app/onbox/` for a two router setup:

```
{
    "config": {
    	"global_retry_interval": 30,
    	"global_retry_count": 5,
    	"ec2_private_endpoint_url": "https://vpce-01c286018e0fad113-vwje496n.ec2.us-west-2.vpce.amazonaws.com",
    	"grpc_server": "127.0.0.1",
    	"grpc_port": 57777,
        "action": {
            "method": "secondary_ip_shift",
            "method_params": {
            	"intf_list": [
            		{
            			"secondary_ip": "172.31.105.10",
			            "instance_intf_number": 2
            		},
            		            		{
            			"secondary_ip": "172.31.101.10",
			            "instance_intf_number": 1
            		}
            	]
            }
        },
    	"bfd_sessions": [
    		{
    			"session_type": "SINGLE_HOP",
	    		"intf_name": "TenGigE0/0/0/2",
	    		"neigh_ip": "172.31.105.206",
	    		"bfd_desired_tx_int_usec": 50000,
		        "detect_multiplier": 3,
		        "vrf_name": "default"
    	    },
            {
            	"session_type": "SINGLE_HOP",
            	"intf_name": "TenGigE0/0/0/1",
    		    "neigh_ip": "172.31.101.101",
	    		"bfd_desired_tx_int_usec": 50000,
		        "detect_multiplier": 3,
		        "vrf_name": "default"
            }
    	]
    	
    }

}

```


The fields are pretty self explanatory. The Mandatory fields are:

1) `"bfd_sessions"`   
2) `"ec2_private_endpoint_url"`
3) `"action"`

For the `"action"` field only the `"secondary_ip_shift"` method is currently supported.




### Create hosts file for the router pair

The host files is set up to eliminate the AWS endpoint-URL DNS lookup which would otherwise increase failover time.
Usually a hosts file would be valid for a HA router pair, but it could be common for all HA router pairs within the same availability zone in the deployment.
A sample hosts file is present under `/core/python/src/app/onbox/` and also shown below.

```
127.0.0.1	localhost.localdomain		localhost
172.31.100.237 vpce-01c286018e0fad113-vwje496n.ec2.us-west-2.vpce.amazonaws.com

```


## Deploy App


#####################################################################################

            STEP 1:  COPY Artifacts to router harddisk

#####################################################################################

--->  Before doing an SCP, enable SCP at higher rates into the routers using the following policing policy for lpts

```
!
lpts pifib hardware police
 flow ssh known rate 15000
 flow ssh default rate 15000
 !
 ```



### SCP App RPM and router specific config.json + hosts file (for predetermined resolution for ec2 endpoint url) to harddisk: (/misc/disk1)

```

scp xrv9k-slbfdha-aws-0.1.0-eXR.x86_64.rpm root@<xrv9k-ip>:/misc/disk1/
scp config_rtr1.json root@<xrv9k-ip>:/misc/disk1/
scp hosts root@<xrv9k-ip>:/misc/disk1/

```

#####################################################################################

            STEP 2:  Install Application RPM and move config files to App Folder

#####################################################################################

### XR CLI exec commands:  

```
# Install RPM
appmgr package install rpm /misc/disk1/xrv9k-slbfdha-aws-0.1.0-eXR.x86_64.rpm

# copy config file to config mount of App
copy harddisk:config_rtr1.json apphost:/appmgr/config/xrv9k_slbfdha_aws/config.json

# copy hosts file to config mount of App
copy harddisk:hosts apphost:/appmgr/config/xrv9k_slbfdha_aws/hosts
```



#####################################################################################

            STEP 3:  Apply CLI configuration to activate app

#####################################################################################


### XR CLI config 

```
# Activate App along with grpc server and routes to metadata and endpoint services


!
bfd
  echo disable
  !
!
appmgr
 application xrv9k_aws_ha
  activate type docker source xrv9k_aws_ha docker-run-opts "-itd --net=host -v {app_install_root}/config/xrv9k_aws_ha/config.json:/app/onbox/config.json -v {app_install_root}/config/xrv9k_aws_ha/hosts:/etc/hosts"
 !
!
!
router static
 address-family ipv4 unicast
  169.254.169.254/32 172.31.100.1
 !
!
tpa
 vrf default
  address-family ipv4
   update-source dataports TenGigE0/0/0/0
  !
 !
 grpc
 port 57777
 no-tls
 service-layer
 !
!

```

 --> The above static route and domain name are used to enable applications in XR to access AWS metadata via the 1st data port




## Monitor Application

Once the application starts running it can be monitored using xr-appmgr commands:


### Running Application Info

```
RP/0/RP0/CPU0:rtr2#show appmgr application name xrv9k_aws_ha info detail 
Tue Jul  6 12:53:09.301 UTC
Application: xrv9k_aws_ha
  Type: Docker
  Source: xrv9k_aws_ha
  Config State: Activated
  Docker Information:
    Container ID: ff9508c510d41c46818f09d423a5f8f5c3e97ed3f212e6db3a56c8024f2e3bc5
    Container name: xrv9k_aws_ha
    Labels: 
    Image: akshshar/xrv9k-aws-ha:latest
    Command: "/usr/local/bin/python3 /root/.local/bin/supervisord -c /etc/supervisord.conf -n"
    Created at: 2021-07-06 11:46:28 +0000 UTC
    Running for: About an hour ago
    Status: Up About an hour
    Size: 4.98MB (virtual 314MB)
    Ports: 
    Mounts: /misc/app_host/appmgr/config/xrv9k_aws_ha/config.json,/misc/app_host/appmgr/config/xrv9k_aws_ha/hosts
    Networks: host
    LocalVolumes: 0
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#

```


### Running Application Stats


```
RP/0/RP0/CPU0:rtr2#show appmgr application name xrv9k_aws_ha stats    
Tue Jul  6 12:53:27.760 UTC
Application Stats: xrv9k_aws_ha
   CPU Percentage: 1.90%
   Memory Usage: 72.91MiB / 15.05GiB
   Memory Percentage: 0.47%
   Network IO: 0B / 0B
   Block IO: 0B / 0B
   PIDs: 0
RP/0/RP0/CPU0:rtr2#

```


### Running Application logs

#### Docker Container logs:

```
RP/0/RP0/CPU0:rtr2#show appmgr application name xrv9k_aws_ha  logs 
Tue Jul  6 12:54:02.808 UTC
2021-07-06 11:46:29,227 CRIT Supervisor is running as root.  Privileges were not dropped because no user is specified in the config file.  If you intend to run as root, you can set user=root in the config file to avoid this message.
2021-07-06 11:46:29,231 CRIT Server 'unix_http_server' running without any HTTP authentication checking
2021-07-06 11:46:29,232 INFO supervisord started with pid 1
2021-07-06 11:46:30,234 INFO spawned: 'ha_app' with pid 6
2021-07-06 11:46:30,235 INFO spawned: 'redis' with pid 7
2021-07-06 11:46:31,237 INFO success: ha_app entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
2021-07-06 11:46:31,237 INFO success: redis entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
2021-07-06 11:51:28,550 WARN received SIGTERM indicating exit request
2021-07-06 11:51:28,550 INFO waiting for ha_app, redis to die
2021-07-06 11:51:28,633 INFO stopped: redis (exit status 0)
2021-07-06 11:51:28,829 INFO stopped: ha_app (exit status 0)
2021-07-06 11:51:36,599 CRIT Supervisor is running as root.  Privileges were not dropped because no user is specified in the config file.  If you intend to run as root, you can set user=root in the config file to avoid this message.
2021-07-06 11:51:36,604 CRIT Server 'unix_http_server' running without any HTTP authentication checking
2021-07-06 11:51:36,604 INFO supervisord started with pid 1
2021-07-06 11:51:37,606 INFO spawned: 'ha_app' with pid 6
2021-07-06 11:51:37,608 INFO spawned: 'redis' with pid 7
2021-07-06 11:51:38,609 INFO success: ha_app entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
2021-07-06 11:51:38,609 INFO success: redis entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
RP/0/RP0/CPU0:rtr2#

```

#### Application Specific logs:

Here the command passed to the docker-exec-command can be used to monitor logs in real time using `tail -f` as shown below or just a dump of the logs using `cat`.

**Note**:  The Application specific logs are automatically log rotated to 1MB.

```
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#appmgr application exec name xrv9k_aws_ha docker-exec-cmd tail -f /var/log/ha_app_bkp.log
Tue Jul  6 12:55:19.545 UTC
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:54:39,667", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576079.667968", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"479", "levelName":"INFO", "message":"Periodic HA state check..."}
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:54:39,779", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576079.779082", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"482", "levelName":"INFO", "message":"HA State: STANDBY"}
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:54:49,779", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576089.779313", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"479", "levelName":"INFO", "message":"Periodic HA state check..."}
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:54:49,900", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576089.900367", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"482", "levelName":"INFO", "message":"HA State: STANDBY"}
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:54:59,900", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576099.900582", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"479", "levelName":"INFO", "message":"Periodic HA state check..."}
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:55:00,016", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576100.016909", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"482", "levelName":"INFO", "message":"HA State: STANDBY"}
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:55:10,017", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576110.017127", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"479", "levelName":"INFO", "message":"Periodic HA state check..."}
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:55:10,130", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576110.130391", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"482", "levelName":"INFO", "message":"HA State: STANDBY"}
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:55:20,130", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576120.130635", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"479", "levelName":"INFO", "message":"Periodic HA state check..."}
Python: { "loggerName":"SL_HA_APP_LOGGER", "asciTime":"2021-07-06 12:55:20,240", "pathName":"/app/onbox/onbox_bfd_ha_app.py", "logRecordCreationTime":"1625576120.240956", "functionName":"check_ha_state", "levelNo":"20", "lineNo":"482", "levelName":"INFO", "message":"HA State: STANDBY"}




```

### Accessing the Application CLI

For convenient state verification and troubleshooting purposes, it is possible to utilize an Application specific json-based CLI that utilizes access to the application's Redis database.
All available cli keys/commands can be checked at any time by running `show redundancy` as an application docker-exec-command as shown below:



#### View Available keys/commands

```
RP/0/RP0/CPU0:rtr2#appmgr application exec name xrv9k_aws_ha docker-exec-cmd show redundancy
Tue Jul  6 12:59:21.789 UTC
[
  "last_bfd_down_event",
  "config",
  "last_intf_event",
  "ha_state",
  "bfd_neighbors",
  "ha_interfaces"
]
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#


```

#### Access Keys/Commands directly using docker-exec "show"

```
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#appmgr application exec name xrv9k_aws_ha docker-exec-cmd show ha_state  
Tue Jul  6 13:00:26.585 UTC

Last Created: 2021/07/06 13:00:24.442059

STANDBY
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#appmgr application exec name xrv9k_aws_ha docker-exec-cmd show bfd_neighbors
Tue Jul  6 13:00:39.300 UTC

Last Created: 2021/07/06 12:09:41.012098

{
  "172.31.105.154": {
    "EventType": "SL_BFD_EVENT_TYPE_SESSION_STATE",
    "Session": {
      "Key": {
        "Type": "SL_BFD_SINGLE_HOP",
        "NbrAddr": 2887739802,
        "Interface": {
          "Name": "TenGigE0/0/0/2"
        }
      },
      "State": {
        "SeqNum": "45",
        "Status": "SL_BFD_SESSION_UP"
      }
    }
  },
  "172.31.101.241": {
    "EventType": "SL_BFD_EVENT_TYPE_SESSION_STATE",
    "Session": {
      "Key": {
        "Type": "SL_BFD_SINGLE_HOP",
        "NbrAddr": 2887738865,
        "Interface": {
          "Name": "TenGigE0/0/0/1"
        }
      },
      "State": {
        "SeqNum": "52",
        "Status": "SL_BFD_SESSION_UP"
      }
    }
  }
}
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#appmgr application exec name xrv9k_aws_ha docker-exec-cmd show config       
Tue Jul  6 13:00:46.610 UTC

Last Created: 2021/07/06 11:51:38.060111

{
  "config": {
    "global_retry_interval": 30,
    "global_retry_count": 5,
    "ec2_private_endpoint_url": "https://vpce-01c286018e0fad113-vwje496n.ec2.us-west-2.vpce.amazonaws.com",
    "grpc_server": "127.0.0.1",
    "grpc_port": 57777,
    "action": {
      "method": "secondary_ip_shift",
      "method_params": {
        "intf_list": [
          {
            "secondary_ip": "172.31.105.20",
            "instance_intf_number": 3
          },
          {
            "secondary_ip": "172.31.101.20",
            "instance_intf_number": 1
          }
        ]
      }
    },
    "bfd_sessions": [
      {
        "session_type": "SINGLE_HOP",
        "intf_name": "TenGigE0/0/0/2",
        "neigh_ip": "172.31.105.154",
        "bfd_desired_tx_int_usec": 50000,
        "detect_multiplier": 3,
        "vrf_name": "default"
      },
      {
        "session_type": "SINGLE_HOP",
        "intf_name": "TenGigE0/0/0/1",
        "neigh_ip": "172.31.101.241",
        "bfd_desired_tx_int_usec": 50000,
        "detect_multiplier": 3,
        "vrf_name": "default"
      }
    ]
  }
}
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#
RP/0/RP0/CPU0:rtr2#appmgr application exec name xrv9k_aws_ha docker-exec-cmd show last_bfd_down_event
Tue Jul  6 13:01:04.561 UTC

Last Created: 2021/07/06 12:11:12.123067

{
  "EventType": "SL_BFD_EVENT_TYPE_SESSION_STATE",
  "Session": {
    "Key": {
      "Type": "SL_BFD_SINGLE_HOP",
      "NbrAddr": 2887738865,
      "Interface": {
        "Name": "TenGigE0/0/0/1"
      }
    },
    "State": {
      "SeqNum": "53",
      "Status": "SL_BFD_SESSION_DOWN"
    }
  }
}
RP/0/RP0/CPU0:rtr2#

```



