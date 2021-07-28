#!/usr/bin/env python3
#
# Copyright (c) 2021 by cisco Systems, Inc. 
# All rights reserved.
# Author: akshshar@cisco.com
#

import redis
import argparse
import ipaddress
import os, sys
import threading, time, datetime
from threading import Event
import boto3
import requests
import pdb
import signal
# gRPC libs
import grpc
import json

from functools import partial
import logging, logging.handlers

# Add the generated python bindings directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# gRPC generated python bindings
from genpy import sl_global_pb2_grpc
from genpy import sl_global_pb2
from genpy import sl_common_types_pb2
from genpy import sl_version_pb2
from genpy import sl_route_ipv4_pb2_grpc
from genpy import sl_route_ipv4_pb2
from genpy import sl_route_common_pb2
from genpy import sl_bfd_common_pb2
from genpy import sl_bfd_ipv4_pb2
from genpy import sl_bfd_ipv4_pb2_grpc
from genpy import sl_interface_pb2
from genpy import sl_interface_pb2_grpc
from google.protobuf import json_format


AWS_METADATA_URL_LATEST="http://169.254.169.254/latest"

EXIT_FLAG = False
#POSIX signal handler to ensure we shutdown cleanly
def handler(sl_bfd_ha, signum, frame):
    global EXIT_FLAG

    if not EXIT_FLAG:
        EXIT_FLAG = True
        sl_bfd_ha.aws_client.syslogger.info("Stopping AWS EC2 resource thread")
        sl_bfd_ha.aws_client.poison_pill.set()
        for thread in sl_bfd_ha.aws_client.threadList:
          sl_bfd_ha.aws_client.syslogger.info("Waiting for %s to finish..." %(thread.name))
          thread.join()
        sl_bfd_ha.syslogger.info("Unregistering SL-API services...")    
        sl_bfd_ha.bfd_regop(sl_common_types_pb2.SL_REGOP_UNREGISTER)
        sl_bfd_ha.bfd_response_stream.cancel()
        sl_bfd_ha.global_event_stream.cancel()
        sl_bfd_ha.intf_response_stream.cancel()
        sl_bfd_ha.poison_pill.set()
        sl_bfd_ha.failover_event.set()
        sl_bfd_ha.failover_complete.set()
        sl_bfd_ha.stop_check_ha_state.set()
        for thread in sl_bfd_ha.threadList:
           sl_bfd_ha.syslogger.info("Waiting for %s to finish..." %(thread.name))
           thread.join()
       # Exit and Kill any running GRPC threads.
        sys.exit(0)




class BaseLogger(object):
    def __init__(self, syslog_server=None, syslog_port=None, syslog_file=None):
        """__init__ constructor
           :param syslog_server: IP address of reachable Syslog Server
           :param syslog_port: Port for the reachable syslog server
           :param syslog_file: Alternative or addon file for syslog
           :type syslog_server: str
           :type syslog_port: int
           :type syslog_file:str
        """
        self.syslog_server = syslog_server
        try:
            self.syslog_port = int(syslog_port)
        except:
            self.syslog_port = None
        self.syslog_file = syslog_file
        self.setup_syslog()


    def setup_syslog(self):
        """Setup up the Syslog logger for remote or local operation
        """

        address = self.syslog_server
        port = self.syslog_port
        filename = self.syslog_file

        logger = logging.getLogger('SL_HA_APP_LOGGER')
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter(
            'Python: { "loggerName":"%(name)s", "asciTime":"%(asctime)s", "pathName":"%(pathname)s", "logRecordCreationTime":"%(created)f", "functionName":"%(funcName)s", "levelNo":"%(levelno)s", "lineNo":"%(lineno)d", "levelName":"%(levelname)s", "message":"%(message)s"}'
        )

        if any([all([address, port]), filename]):

            #add handler to the logger
            if all([address, port]):
                remotehandler = logging.handlers.SysLogHandler(
                    address=(address, port))
                remotehandler.formatter = formatter
                logger.addHandler(remotehandler)

            if filename is not None:
                filehandler = logging.FileHandler(filename)
                filehandler.formatter = formatter
                logger.addHandler(filehandler)

        else:
            MAX_SIZE = 1024 * 1024 * 10
            LOG_PATH = "/var/log/ha_app_bkp.log"
            handler = logging.handlers.RotatingFileHandler(
                LOG_PATH, maxBytes=MAX_SIZE, backupCount=2)
            handler.formatter = formatter
            logger.addHandler(handler)

        self.syslogger = logger



class AWSClient(BaseLogger):


    def __init__(self,
                 syslogger=None,
                 endpoint_url=None):

        #super(AWSClient, self).__init__(syslog_file=syslog_file,
        #                                syslog_server=syslog_server,
        #                                syslog_port=syslog_port)
        if syslogger is None:
            logging.error("Initialize the baselogger class and pass in the syslogger handle. Aborting...")
            self.exit = True
            return
        else:
            self.syslogger = syslogger
        
        self.threadList = []
        self.metadata_url_latest=AWS_METADATA_URL_LATEST
        self.endpoint_url = endpoint_url
        self.exit = False
        self.poison_pill= Event()
        self.resource_created = Event()
        self.token_header=""
        self.start_time=datetime.datetime.now()
        self.resource = None
        for fn in [self.setup_ec2_client]:
            thread = threading.Thread(target=fn, args=())
            self.threadList.append(thread)
            thread.daemon = True                            # Daemonize thread
            thread.start()                                  # Start the execution
       
        while not self.resource_created.is_set():
            self.resource_created.wait(30) # Sleep for 30 seconds max to allow the resource to be created 


    def generate_token(self):
        headers = {
            'X-aws-ec2-metadata-token-ttl-seconds': '21600',
        }

        try:
            response = requests.put(self.metadata_url_latest+"/api/token", headers=headers)
            self.token = response.text
            self.token_header=  {
                                    'X-aws-ec2-metadata-token': self.token,
                                }
        except Exception as e:
            self.syslogger.info("Failed to fetch token for AWS interactions. error: " +str(e))


    def fetch_iam_role_name(self):
        if self.token_header != "":
            try:
                response = requests.get(self.metadata_url_latest+"/meta-data/iam/security-credentials/", headers=self.token_header)
                self.rolename = response.text 
            except Exception as e:
                self.syslogger.info("Failed to fetch attached IAM role name. error: " +str(e))
                self.exit= True
        else:
            self.syslogger.info("No token available, cannot fetch IAM role name, bailing out....")
            self.exit =  True

    def fetch_temp_credentials(self):
        if self.token_header != "":
            try:
                response = requests.get(self.metadata_url_latest+"/meta-data/iam/security-credentials/"+str(self.rolename), headers=self.token_header)
                self.access_key=response.json()["AccessKeyId"]
                self.secret_key=response.json()["SecretAccessKey"]
                self.session_token=response.json()["Token"]
            except Exception as e:
                self.syslogger.info("Failed to fetch temporary credentials for AWS interactions. error: " +str(e))
                self.exit= True
        else:
            self.syslogger.info("No token available, cannot fetch temp credentials, bailing out....")
            self.exit =  True

    def fetch_instance_region(self):
        if self.token_header != "":
            try:
                response = requests.get(self.metadata_url_latest+"/meta-data/placement/region", headers=self.token_header)
                self.region_name=response.text
            except Exception as e:
                self.syslogger.info("Failed to fetch instance region. error: " +str(e))
                self.exit= True
        else:
            self.syslogger.info("No token available, cannot fetch instance region, bailing out....")
            self.exit =  True
            

    def fetch_self_instance_id(self):
        if self.token_header != "":
            try:
                response = requests.get(self.metadata_url_latest+"/meta-data/instance-id", headers=self.token_header)
                self.instance_id=response.text
            except Exception as e:
                self.syslogger.info("Failed to fetch instance ID. error: " +str(e))
                self.exit= True
        else:
            self.syslogger.info("No token available, cannot fetch instance ID, bailing out....")
            self.exit =  True

    def setup_boto_resource(self):
        if not self.exit:
            try:
                if self.endpoint_url is None:
                    self.syslogger.info("Endpoint URL not specified, cannot create resource...")
                    raise Exception("Endpoint URL is empty")

                self.resource = boto3.resource(
                                    service_name='ec2',
                                    endpoint_url=self.endpoint_url,
                                    aws_access_key_id=self.access_key,
                                    aws_secret_access_key=self.secret_key,
                                    aws_session_token=self.session_token,
                                    region_name=self.region_name
                                )
                self.resource_created.set()
            except Exception as e:
                self.syslogger.info("Failed to create boto resource for AWS EC2 services. error: " +str(e))
                self.exit= True
        else:
            self.syslogger.info("Failed to fetch one or more of the AWS metadata fields")


    def setup_ec2_client(self):

        set_up=True
        while True:
            self.syslogger.info("Checking if temporary credentials need to be refreshed...")
            self.call_time=datetime.datetime.now()
            time_elapsed = self.call_time -  self.start_time
            time_elapsed_minutes = (int(time_elapsed.total_seconds())/60)

            self.syslogger.info("time_elapsed:")
            self.syslogger.info(time_elapsed)
            self.syslogger.info(time_elapsed_minutes)

            if (time_elapsed_minutes >= 10) or (set_up): 
                if not set_up:
                    self.syslogger.info("10 minutes elapsed, refreshing temporary credentials")
                self.generate_token()
                self.fetch_iam_role_name() 
                self.fetch_temp_credentials()
                self.fetch_instance_region()
                self.fetch_self_instance_id()
                self.setup_boto_resource()
                if not self.exit:
                    self.start_time = datetime.datetime.now()
                    self.syslogger.info("Initial Setup done. Start refreshing credentials periodically")
                    set_up=False
                else:
                    self.syslogger.info("Failed to set up AWS client resource. Will try again in some time...")
            else:
                self.syslogger.info("Credentials should still be valid, will check again in 5 mins..")

                if not self.poison_pill.wait(300): # Sleep for 5 mins before checking validity of credentials again
                    self.syslogger.info("Completed 5 mins, checking credentials again")

                if self.poison_pill.is_set():
                    self.syslogger.info("Received poison pill, terminating setup_ec2_client thread...")
                    return {"status": "error", "output": "Received poison pill, terminating setup_ec2_client thread", "resource": None}
                    





class SLHaBfd(BaseLogger):


    def __init__(self,
                 config_file="/root/config.json"):

        self.exit =  False
        if config_file is None:
            logging.error("Input json config file not provided, aborting...")
            self.exit = True 
            return
        else:
            self.config_file = config_file


        # Read and load the input config.json file
        try:
            with open(self.config_file, 'r') as json_config_fd:
                self.config_json = json.load(json_config_fd)
        except Exception as e:
            logging.error("Failed to load config file. Aborting...")
            self.exit = True
            return

        if "syslog_file" in self.config_json["config"]:
            syslog_file = self.config_json["config"]["syslog_file"]
        else:
            syslog_file = None 

        if ("syslog_server" in self.config_json["config"]) and ("syslog_port" in self.config_json["config"]):
            syslog_server = self.config_json["config"]["syslog_server"]
            syslog_port = self.config_json["config"]["syslog_port"]
        else:
            syslog_server = None
            syslog_port = None



        super(SLHaBfd, self).__init__(syslog_file=syslog_file,
                                      syslog_server=syslog_server,
                                      syslog_port=syslog_port)


        if "ec2_private_endpoint_url" in self.config_json["config"]:
            endpoint_url = self.config_json["config"]["ec2_private_endpoint_url"]
        else:
            endpoint_url = "ec2.us-west-2.amazonaws.com"

        self.aws_client = AWSClient(syslogger=self.syslogger,
                                    endpoint_url=endpoint_url)

        if not self.aws_client.exit:
            if self.aws_client.resource is not None:
                self.syslogger.info("EC2 resource client created")
            else:
                self.syslogger.info("Failed to create AWS client resource. Aborting...")
                self.exit = True
                return
        else:
            self.syslogger.info("Failed to create AWS client resource. Aborting...")
            self.exit = True
            return


        
        self.instance_id = self.aws_client.instance_id
        #self.instance_id = self.config_json["config"]["instance_id"]
     
        if "grpc_server" in self.config_json["config"]:
            grpc_server_ip = self.config_json["config"]["grpc_server"]
        else:
            self.syslogger.info("gRPC server not specified in input config file, defaulting to 127.0.0.1")
            grpc_server_ip ="127.0.0.1"

        if "grpc_port" in self.config_json["config"]:
            grpc_server_port = self.config_json["config"]["grpc_port"]
        else:
            self.syslogger.info("gRPC port not specified in input config file, defaulting to 57777")
            grpc_server_port = 57777

        if "global_retry_count" in self.config_json["config"]:
            self.global_retry_count  = self.config_json["config"]["global_retry_count"]
        else:
            self.syslogger.info("global_retry_count not specified in input config file, defaulting to 5")
            self.global_retry_count  = 5

        if "global_retry_interval" in self.config_json["config"]:
            self.global_retry_interval  = self.config_json["config"]["global_retry_interval"]
        else:
            self.syslogger.info("global_retry_interval not specified in input config file, defaulting to 30")
            self.global_retry_interval  = 30


        if "redis_server" in self.config_json["config"]:
            redis_server = self.config_json["config"]["redis_server"]
        else:
            self.syslogger.info("Redis server IP not specified in input config file, defaulting to 127.0.0.1")
            redis_server ="127.0.0.1"

        if "redis_port" in self.config_json["config"]:
            redis_port = self.config_json["config"]["redis_port"]
        else:
            self.syslogger.info("redis port not specified in input config file, defaulting to 6379")
            redis_port = 6379


        self.threadList = []
        self.syslogger.info("Using GRPC Server IP(%s) Port(%s)" %(grpc_server_ip, grpc_server_port))
       
        # Create the channel for gRPC.
        self.channel = grpc.insecure_channel(str(grpc_server_ip)+":"+
                                                   str(grpc_server_port))
        

        self.global_event = Event()
        self.poison_pill= Event()

        self.redis = redis.StrictRedis(host=str(redis_server), port=int(redis_port))
        self.redis.flushall()
        self.update_redis("config", json.dumps(self.config_json))

        # Spawn a thread to Initialize the client and listen on notifications
        # The thread will run in the background
        self.global_init(self.channel)
        
        if self.exit:
            self.syslogger.info("Failed to start global gRPC thread, exiting...")
            return

        self.threadList.append(self.global_thread)


        self.bfd_neighbors = {}
        self.failover_event = Event()
        self.failover_complete = Event()
        self.stop_check_ha_state =  Event()
        self.action_hash = {}
        self.secondary_ip_hash = {}
        self.interface_state_hash = {}
        self.ha_state="UNKNOWN"
        self.ha_interfaces= {}
        check_status = self.check_secondary_ip()

        if check_status["status"] == "error":
            self.syslogger.info("Failed to check secondary IP status during init. Aborting...")
            self.exit = True
            return

        self.action_pool()


        # Create the SL-BFD gRPC stub and register
        self.stub = sl_bfd_ipv4_pb2_grpc.SLBfdv4OperStub(self.channel)

        # Intf Stub to check intf status before failover ensuring make before break
        self.intfstub = sl_interface_pb2_grpc.SLInterfaceOperStub(self.channel)

        self.bfd_regop(sl_common_types_pb2.SL_REGOP_REGISTER)
        self.bfd_regop(sl_common_types_pb2.SL_REGOP_EOF)

        self.intf_regop(sl_common_types_pb2.SL_REGOP_REGISTER)
        self.intf_regop(sl_common_types_pb2.SL_REGOP_EOF)


        try:
            for bfd_session in self.config_json["config"]["bfd_sessions"]:
                bfd_session["bfd_oper"] = sl_common_types_pb2.SL_OBJOP_UPDATE
                self.bfd_op(**bfd_session)
                self.intf_enable_notif(bfd_session['intf_name'])
        
        except Exception as e:
            self.syslogger.info("Failed to set up BFD sessions. Error: "+str(e))
            self.exit = True


        for fn in [self.bfd_notifications, self.intf_notifications, self.check_ha_state]:
            thread = threading.Thread(target=fn, args=())
            self.threadList.append(thread)
            thread.daemon = True                            # Daemonize thread
            thread.start()                                  # Start the execution



    def update_redis(self, key=None, value=None):
        try:
            if not self.poison_pill.is_set():
                self.redis.sadd("redundancy", str(key))
                combined_value = {'value': value,
                                  'timestamp': datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')}
                self.redis.hset(key, mapping=combined_value)
                for key in self.redis.scan_iter():
                    print(key)
        except Exception as e:
            self.syslogger.info("Failed to update Redis database.Error: "+str(e))


    def check_ha_state(self):
        while not self.stop_check_ha_state.is_set():
            self.stop_check_ha_state.wait(10)
            self.syslogger.info("Periodic HA state check...")
            check_status = self.check_secondary_ip(debug=False)

            if check_status["status"] == "error":
                self.syslogger.info("Unable to check secondary IP status, forcing state to UNKNOWN")
                self.converge_ha_state(force_state="UNKNOWN")
            else:
                self.converge_ha_state(debug=False) 
            self.syslogger.info("HA State: "+str(self.ha_state))


    def check_secondary_ip(self, debug=True):
        if debug:
            self.syslogger.setLevel(logging.DEBUG)
        else:
            self.syslogger.setLevel(logging.INFO)

        action = self.config_json["config"]["action"]
        if action["method"] == "secondary_ip_shift":
            if not "method_params" in action:
                self.syslogger.info("No method_params specified for action=secondary_ip_shift...") 
                return  {"status": "error", "output": "No method_params specified"} 
            else:
                try:
                    interface_map = {}
                    for interface in action["method_params"]["intf_list"]:
                        secondary_ip = interface["secondary_ip"]
                        interface_num = interface["instance_intf_number"]
                        
                        instance = self.aws_client.resource.Instance(self.instance_id)
                        self.syslogger.debug(instance.network_interfaces)

                        intf_index = None
                        for instance_net_intf in instance.network_interfaces:
                            if interface_num == instance_net_intf.attachment["DeviceIndex"]:
                                intf_index = instance.network_interfaces.index(instance_net_intf)
                                break
 
                        if intf_index is not None:
                            intf_private_ips = instance.network_interfaces[intf_index].private_ip_addresses
                            intf_eni_id = instance.network_interfaces[intf_index].id
                            interface_map[intf_eni_id] = {"interface_num": interface_num, 
                                                          "private_ip_addresses": intf_private_ips}
                            self.syslogger.debug(intf_private_ips)
                            match=False
                            for intf_private_ip in intf_private_ips:
                                if not intf_private_ip['Primary']:
                                    if intf_private_ip['PrivateIpAddress'] == secondary_ip:
                                        self.syslogger.debug("Secondary IP for interface" +str(interface_num)+" with eni-id: "+str(intf_eni_id)+" matches desired secondary IP: "+str(secondary_ip)+" for HA pair")
                                        self.secondary_ip_hash[str(interface_num)] = True
                                        match=True
                                        break

                            if not match:            
                                self.syslogger.debug(" NO Secondary IP for interface" +str(interface_num)+" with eni-id: "+str(intf_eni_id)+" matches desired secondary IP: "+str(secondary_ip)+" for HA pair")
                                self.secondary_ip_hash[str(interface_num)] = False
                        else:
                            self.syslogger.info("Failed to find instance interface with matching DeviceIndex")
                            return  {"status": "error", "output": "Failed to find instance interface with matching DeviceIndex"}

                    self.update_redis("ha_interfaces", json.dumps(interface_map))
                    return  {"status": "success"}

                except Exception as e:
                    self.syslogger.info("Failed to check the current secondary IP status on instance. Error: "+str(e))
                    return  {"status": "error", "output": "Failed to check the current secondary IP status on instance"}
 
        self.syslogger.setLevel(logging.INFO)
           
    def converge_ha_state(self, action="secondary_ip_shift", debug=True, force_state=None):
        # Three HA states are defined for a node
        # UNKNOWN:  This is the default state when a node first boots up (HA app comes up) or post failure + reboot
        # ACTIVE:  When the current node is handling traffic (If secondary_ip_shift action is used, then current node must own the secondary IPs)
        # STANDBY: When the current node is not handling traffic (If secondary_ip_shift action is used, then current node does not own the secondary IPs)

        # This method sets the HA state of the node when invoked

        if debug:
            self.syslogger.setLevel(logging.DEBUG)
        else:
            self.syslogger.setLevel(logging.INFO)
        try:
            if force_state is not None:
                self.ha_state = str(force_state)
            else:    
                if action == "secondary_ip_shift":
                    self.syslogger.debug(self.secondary_ip_hash)
                    if all(val==True for val in self.secondary_ip_hash.values()):
                        self.syslogger.debug("All the secondary IPs assigned to local node, setting ha_state to ACTIVE")
                        self.ha_state = "ACTIVE"
                    elif all(val==False for val in self.secondary_ip_hash.values()):
                        self.syslogger.debug("None of the secondary IPs assigned to local node, setting ha_state to STANDBY")
                        self.ha_state = "STANDBY"
                    else:
                        self.syslogger.debug("Not all interfaces converged properly, setting ha_state to UNKNOWN")
                        self.ha_state = "UNKNOWN"

            self.update_redis("ha_state", str(self.ha_state))
        except Exception as e:
            self.syslogger.info("Failed to converge HA state. Set to UNKNOWN. Error: "+str(e))
            self.ha_state = "UNKNOWN"

        self.syslogger.setLevel(logging.INFO)


    def action_pool(self):
        action = self.config_json["config"]["action"]
        if action["method"] == "secondary_ip_shift":
            if not "method_params" in action:
                self.syslogger.info("No method_params specified for action=secondary_ip_shift...") 
                return  {"status": "error", "output": "No method_params specified"} 
            else:
                try:
                    thread_index=0
                    for interface in action["method_params"]["intf_list"]:
                        secondary_ip = interface["secondary_ip"]
                        interface_num = interface["instance_intf_number"]
                        instance = self.aws_client.resource.Instance(self.instance_id)
                        intf_index = None
                        for instance_net_intf in instance.network_interfaces:
                            if interface_num == instance_net_intf.attachment["DeviceIndex"]:
                                intf_index = instance.network_interfaces.index(instance_net_intf)
                                break 
                        thread = threading.Thread(target=self.action_thread_secondary_ip_shift, args=(secondary_ip, intf_index, thread_index,))
                        self.syslogger.info("Starting Action thread "+str(thread.name))
                        self.threadList.append(thread)
                        thread.daemon = True                            # Daemonize thread
                        thread.start()                                  # Start the execution

                        thread_index +=1
                except Exception as e:
                    self.syslogger.info("Failed to set up action thread pool for secondary_ip shift. Error: "+str(e))


    def action_thread_secondary_ip_shift(self, secondary_ip=None, interface_num=None, thread_index=None):
        while True:
            if self.poison_pill.is_set():
                self.syslogger.info("Poison Pill received, terminating action thread")
                return

            if any([secondary_ip, interface_num, thread_index]) is None:
                self.syslogger.info("Missing input parameters")
                self.syslogger.info(secondary_ip)
                self.syslogger.info(interface_num)
                self.syslogger.info(thread_index)
            else:
                self.action_hash[thread_index] = False
                self.syslogger.info("Inside Action thread: Waiting for failover event")
                self.failover_event.wait() # Sleep until the failover event occurs

                self.syslogger.info("Inside Action thread: Failover event detected, perform action")
                if self.poison_pill.is_set():
                    self.syslogger.info("Poison Pill received, terminating action thread")
                    return
                if self.failover_event.is_set(): 
                    try:
                        instance = self.aws_client.resource.Instance(self.instance_id)
                        intf_private_ips = instance.network_interfaces[int(interface_num)].private_ip_addresses
                        self.syslogger.info(intf_private_ips)

                        instance.network_interfaces[int(interface_num)].assign_private_ip_addresses(AllowReassignment=True, 
                                                                                                PrivateIpAddresses=[secondary_ip])
                        self.action_hash[thread_index] = True
                        self.syslogger.info("Inside Action thread: Completed Action. Waiting for failover complete event")
                        self.failover_complete.wait()
                        self.syslogger.info("Inside Action thread: Failover complete")
                        if self.poison_pill.is_set():
                            self.syslogger.info("Poison Pill received, terminating action thread")
                            return
                    except Exception as e:
                        self.syslogger.info("Failed to apply secondary_ip:"+str(secondary_ip)+" to interface num: "+str(interface_num))



    def intf_regop(self, intf_regop):
        
        intfRegMsg = sl_interface_pb2.SLInterfaceGlobalsRegMsg()
        intfRegMsg.Oper = intf_regop

        #
        # Make an RPC call
        #
        Timeout = 10 # Seconds
        response = self.intfstub.SLInterfaceGlobalsRegOp(intfRegMsg, Timeout)
        #self.syslogger.info(response)

        #
        # Check the received result from the Server
        #
        try:
            if (response.StatusSummary.Status ==
                sl_common_types_pb2.SLErrorStatus.SL_SUCCESS):
                self.syslogger.info("Interface %s Success!" %(
                    list(sl_common_types_pb2.SLRegOp.keys())[intf_regop]))
            else:
                self.syslogger.info("Error code for Interface %s is 0x%x! Response:" % (
                    list(sl_common_types_pb2.SLRegOp.keys())[intf_regop],
                    response.StatusSummary.Status
                ))
                self.syslogger.info(response)
                # If we have partial failures within the batch, let's print them
                if (response.StatusSummary.Status ==
                    sl_common_types_pb2.SLErrorStatus.SL_SOME_ERR):
                    for result in response.Results:
                        self.syslogger.info("Error code for %s is 0x%x" %(result.VrfName,
                            result.ErrStatus.Status
                        ))
                return
        except Exception as e:
            self.syslogger.info(e)


    def bfd_regop(self, bfd_regop):
        
        bfdRegMsg = sl_bfd_common_pb2.SLBfdRegMsg()
        bfdRegMsg.Oper = bfd_regop

        #
        # Make an RPC call
        #
        Timeout = 10 # Seconds
        response = self.stub.SLBfdv4RegOp(bfdRegMsg, Timeout)
        #self.syslogger.info(response)

        #
        # Check the received result from the Server
        #
        try:
            if (response.StatusSummary.Status ==
                sl_common_types_pb2.SLErrorStatus.SL_SUCCESS):
                self.syslogger.info("BFD %s Success!" %(
                    list(sl_common_types_pb2.SLRegOp.keys())[bfd_regop]))
            else:
                self.syslogger.info("Error code for BFD %s is 0x%x! Response:" % (
                    list(sl_common_types_pb2.SLRegOp.keys())[bfd_regop],
                    response.StatusSummary.Status
                ))
                self.syslogger.info(response)
                # If we have partial failures within the batch, let's print them
                if (response.StatusSummary.Status ==
                    sl_common_types_pb2.SLErrorStatus.SL_SOME_ERR):
                    for result in response.Results:
                        self.syslogger.info("Error code for %s is 0x%x" %(result.VrfName,
                            result.ErrStatus.Status
                        ))
                return
        except Exception as e:
            self.syslogger.info(e)


    def intf_enable_notif(self,
                          intf_name=None):


        if intf_name is not None:
            intf_notif_op = sl_interface_pb2.SLInterfaceNotifMsg()

            intf_notif_op.Oper = sl_common_types_pb2.SL_NOTIFOP_ENABLE
            intf_name_list = []
            interface = sl_common_types_pb2.SLInterface()
            interface.Name = intf_name

            # Possible states in hash = SL_IF_STATE_UNKNOWN / SL_IF_STATE_DOWN / SL_IF_STATE_UP
            self.interface_state_hash[intf_name] = "SL_IF_STATE_UNKNOWN"
            intf_name_list.append(interface)

            intf_notif_op.Entries.extend(intf_name_list)
              
            try:
                Timeout = 10
                response = self.intfstub.SLInterfaceNotifOp(intf_notif_op, Timeout)
            except Exception as e:
                self.syslogger.info("Failed to enable notifications for interface: "+str(intf_name)+". Error: "+str(e))



    def bfd_op(self, 
               bfd_oper=None,
               session_type=None,
               intf_name=None,
               source_ip=None,
               neigh_ip=None,
               bfd_desired_tx_int_usec=50000,
               detect_multiplier=3,
               vrf_name="default"):
        #
        # Make an RPC call
        #
        Timeout = 10 # Seconds

        bfdv4session = sl_bfd_ipv4_pb2.SLBfdv4SessionCfg()

        if session_type == "SINGLE_HOP":
            bfdv4session.Key.Type = sl_bfd_common_pb2.SLBfdType.SL_BFD_SINGLE_HOP
            bfdv4session.Key.Interface.Name = intf_name
        elif session_type == "MULTI_HOP":
            bfdv4session.Key.Type = sl_bfd_common_pb2.SLBfdType.SL_BFD_MULTI_HOP
            bfdv4session.Key.SourceAddr = int(ipaddress.ip_address(source_ip))

        bfdv4session.Key.VrfName = vrf_name
        #bfdv4session.Key.Interface.Name = intf_name
        bfdv4session.Key.NbrAddr = int(ipaddress.ip_address(neigh_ip))
        bfdv4session.Config.DesiredTxIntUsec = int(bfd_desired_tx_int_usec)
        bfdv4session.Config.DetectMultiplier = int(detect_multiplier)


        bfdv4Msg = sl_bfd_ipv4_pb2.SLBfdv4Msg()
        bfdv4Msg.Oper = bfd_oper

        bfdv4sessions = []
        bfdv4sessions.append(bfdv4session)
        bfdv4Msg.Sessions.extend(bfdv4sessions)

        response = self.stub.SLBfdv4SessionOp(bfdv4Msg, Timeout)


    def intf_notifications(self):

        intf_getnotif_msg = sl_interface_pb2.SLInterfaceGetNotifMsg()

        try:
            while True:
                if self.poison_pill.is_set():
                    self.syslogger.info("Poison Pill received, terminating Interface notifications thread")
                    return
                self.syslogger.info("Starting listener for interface events")
                self.intf_response_stream = self.intfstub.SLInterfaceGetNotifStream(intf_getnotif_msg)
                for response in self.intf_response_stream:
                    self.syslogger.info(response)
                    response_dict = json_format.MessageToDict(response)
                    self.update_redis("last_intf_event", json.dumps(response_dict))
                    intf_name = response_dict["Info"]["SLIfInfo"]["Name"]
                    state = response_dict["Info"]["IfState"]
                    self.interface_state_hash[intf_name] = state
                    self.syslogger.info(self.interface_state_hash)

        except Exception as e:
            self.syslogger.info("Exception occured while listening to Interface notifications")
            self.syslogger.info(e)


    def bfd_notifications(self):
        bfd_get_notif_msg = sl_bfd_common_pb2.SLBfdGetNotifMsg()
        #Timeout = 3600*24*365

        try:
            while True:
                if self.poison_pill.is_set():
                    self.syslogger.info("Poison Pill received, terminating BFD notifications thread")
                    return

                self.converge_ha_state()
                self.syslogger.info("Starting listener for BFD events")
                # Set Timeout if needed
                self.bfd_response_stream = self.stub.SLBfdv4GetNotifStream(bfd_get_notif_msg)
                for response in self.bfd_response_stream:
                    self.syslogger.info(response)
                    response_dict = json_format.MessageToDict(response)

                    # Listen to BFD DOWN notification only in STANDBY ha_state

                    if response_dict['Session']['State']['Status'] == 'SL_BFD_SESSION_DOWN':
                        if self.ha_state == "STANDBY":
                            self.syslogger.info(self.interface_state_hash[response_dict['Session']['Key']['Interface']['Name']])
                            intf_name = response_dict['Session']['Key']['Interface']['Name']
                            if self.interface_state_hash[intf_name] == "SL_IF_STATE_DOWN":
                                self.syslogger.info("Local interface went down, ignore BFD session event")
                            else:
                                self.syslogger.info("BFD Peer is DOWN. Current HA state is STANDBY, performing configured action...")            
                                self.failover_event.set()
                                while not all(val==True for val in self.action_hash.values()):
                                    self.failover_complete.wait(0.05)

                                self.syslogger.info(self.action_hash)
                                self.failover_event.clear()
                                self.failover_complete.set()

                        elif self.ha_state == "ACTIVE":
                            self.syslogger.info("Current HA state is Active. Ignoring BFD session DOWN notifications")
                        else:
                            self.syslogger.info("Current HA state is UNKNOWN - ignore current BFD notifications and reconverge HA state")

                        self.update_redis("last_bfd_down_event", json.dumps(response_dict))
                        self.syslogger.info("Reconverging HA state...")
                        self.check_secondary_ip()
                        self.converge_ha_state()     
                    elif response_dict['Session']['State']['Status'] == 'SL_BFD_SESSION_UP':
                        neigh_ip = ipaddress.ip_address(response_dict['Session']['Key']['NbrAddr']).__str__()
                        self.bfd_neighbors[neigh_ip] = response_dict
                        self.update_redis("bfd_neighbors", json.dumps(self.bfd_neighbors))
 

        except Exception as e:
            self.syslogger.info("Exception occured while listening to BFD notifications")
            self.syslogger.info(e)



    def client_init(self, stub):
        #
        # Create SLInitMsg to handshake the version number with the server.
        # The Server will allow/deny access based on the version number.
        # The same RPC is used to setup a notification channel for global
        # events coming from the server.
        #
        # # Set the client version number based on the current proto files' version
        init_msg = sl_global_pb2.SLInitMsg()
        init_msg.MajorVer = sl_version_pb2.SL_MAJOR_VERSION
        init_msg.MinorVer = sl_version_pb2.SL_MINOR_VERSION
        init_msg.SubVer = sl_version_pb2.SL_SUB_VERSION

        # Set a very large timeout, as we will "for ever" loop listening on
        # notifications from the server
        #Timeout = 365*24*60*60 # Seconds
        #Timeout = 5

        try:
            while True:
                if self.poison_pill.is_set():
                    self.syslogger.info("Poison Pill received, terminating global init thread")
                    return
                # This for loop will never end unless the server closes the session
                # Set Timeout later if needed
                self.global_event_stream = stub.SLGlobalInitNotif(init_msg)
                for response in self.global_event_stream:
                    if response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_VERSION:
                        if (sl_common_types_pb2.SLErrorStatus.SL_SUCCESS ==
                                response.ErrStatus.Status) or \
                            (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_CLEAR ==
                                response.ErrStatus.Status) or \
                            (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_READY ==
                                response.ErrStatus.Status):
                            self.syslogger.info("Server Returned 0x%x, Version %d.%d.%d" %(
                                response.ErrStatus.Status,
                                response.InitRspMsg.MajorVer,
                                response.InitRspMsg.MinorVer,
                                response.InitRspMsg.SubVer))
                            self.syslogger.info("Successfully Initialized, connection established!")
                            # Any thread waiting on the global event can proceed
                            self.global_event.set()
                        else:
                            self.syslogger.info("client init error code 0x%x", response.ErrStatus.Status)
                            return
                    elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_HEARTBEAT:
                        self.syslogger.info("Received HeartBeat")
                    elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_ERROR:
                        if (sl_common_types_pb2.SLErrorStatus.SL_NOTIF_TERM ==
                                response.ErrStatus.Status):
                            self.syslogger.info("Received notice to terminate. Client Takeover?")
                            self.syslogger.info("Setting poison pill")
                            return
                        else:
                            self.syslogger.info("Error not handled:", response)
                    else:
                        self.syslogger.info("client init unrecognized response %d", response.EventType)
                        self.syslogger.info("Setting poison pill")
                        return

        except Exception as e:
            self.syslogger.info("Exception occured while listening to Global HeartBeat notifications")
            self.syslogger.info(e)
            return

    #
    # Spawn a thread for global gRPC events
    #
    def global_init(self,channel):
        # Create the gRPC stub.
        stub = sl_global_pb2_grpc.SLGlobalStub(channel)


        iteration = 0
        attempt_thread = True
        while True:

            if attempt_thread:
                # The main reason we spawn a thread here, is that we dedicate a GRPC
                # channel to listen on Global asynchronous events/notifications.
                # This thread will be handling these event notifications.
                self.global_thread = threading.Thread(target = self.client_init, args=(stub,))
                self.global_thread.daemon = True
                self.global_thread.start()

            # Wait for the global_event to be set and retry as needed:
            while not self.global_event.is_set():
                self.syslogger.info("Global Event not set yet, wait for retry interval = "+str(self.global_retry_interval)+" seconds.")
                global_event_flag = self.global_event.wait(self.global_retry_interval)
                if not global_event_flag:
                    self.global_thread.join(timeout=5)
                    if not self.global_thread.is_alive():
                        attempt_thread = True
                    else:
                        attempt_thread = False
                    # Timeout occured, increment iterator and try again
                    iteration +=1
                    break

            if self.global_event.is_set():
                self.syslogger.info("Global Event Set!")
                self.exit = False
                return

            if iteration < self.global_retry_count:
                self.syslogger.info("Failed to connect to the gRPC server, trying again....")
            else:
                self.syslogger.info("Unable to connect to gRPC server, retries exceeded. Bailing out...")
                self.exit = True
                return


        # # Wait for the spawned thread before proceeding
        # self.global_event.wait()

        # Get the globals. Create a SLGlobalsGetMsg
        global_get = sl_global_pb2.SLGlobalsGetMsg()

        #
        # Make an RPC call to get global attributes
        #
        Timeout = 10 # Seconds
        response = stub.SLGlobalsGet(global_get, Timeout)

        # Check the received result from the Server
        if (response.ErrStatus.Status ==
            sl_common_types_pb2.SLErrorStatus.SL_SUCCESS):
            self.syslogger.info("Max VRF Name Len     : %d" %(response.MaxVrfNameLength))
            self.syslogger.info("Max Iface Name Len   : %d" %(response.MaxInterfaceNameLength))
            self.syslogger.info("Max Paths per Entry  : %d" %(response.MaxPathsPerEntry))
            self.syslogger.info("Max Prim per Entry   : %d" %(response.MaxPrimaryPathPerEntry))
            self.syslogger.info("Max Bckup per Entry  : %d" %(response.MaxBackupPathPerEntry))
            self.syslogger.info("Max Labels per Entry : %d" %(response.MaxMplsLabelsPerPath))
            self.syslogger.info("Min Prim Path-id     : %d" %(response.MinPrimaryPathIdNum))
            self.syslogger.info("Max Prim Path-id     : %d" %(response.MaxPrimaryPathIdNum))
            self.syslogger.info("Min Bckup Path-id    : %d" %(response.MinBackupPathIdNum))
            self.syslogger.info("Max Bckup Path-id    : %d" %(response.MaxBackupPathIdNum))
            self.syslogger.info("Max Remote Bckup Addr: %d" %(response.MaxRemoteAddressNum))
        else:
            self.syslogger.info("Globals response Error 0x%x" %(response.ErrStatus.Status))
            self.poison_pill.set()
            self.exit = True
            return






#
# Setup the GRPC channel with the server, and issue RPCs
#
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config-file', dest='config_file', default="/root/config.json",
                    help='Specify path to the json config file for HA App')

    argobj= parser.parse_args()

    if argobj.config_file is None:
        logging.error("No Input config provided, bailing out.... Please provide a compatible json input file")
        sys.exit(1)

    
    
    # Set up the SLBFD object
    sl_bfd_ha =  SLHaBfd(config_file=argobj.config_file)
    if sl_bfd_ha.exit:
        logging.error("Failed to initialize the HA app object, aborting")
        sys.exit(1)
          

    # Register our handler for keyboard interrupt and termination signals
    signal.signal(signal.SIGINT, partial(handler, sl_bfd_ha))
    signal.signal(signal.SIGTERM, partial(handler, sl_bfd_ha))

    # The process main thread does nothing but wait for signals
    signal.pause() 

    # RPC EOF to cleanup any previous stale BFD sessions 
    #bfd_regop(channel, sl_common_types_pb2.SL_REGOP_EOF)

    sys.exit(0)
