#!/usr/bin/env python3
#
# Copyright (c) 2021 by cisco Systems, Inc. 
# All rights reserved.
# Author: akshshar@cisco.com
#


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

from functools import partial
import logging, logging.handlers

# Add the generated python bindings directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

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


AWS_METADATA_URL_LATEST="http://169.254.169.254/latest/"

EXIT_FLAG = False
#POSIX signal handler to ensure we shutdown cleanly
def handler(sl_bfd_ha, aws_ec2_resource, signum, frame):
    global EXIT_FLAG

    if not EXIT_FLAG:
        EXIT_FLAG = True
        aws_ec2_resource.syslogger.info("Stopping AWS EC2 resource thread")
        aws_ec2_resource.poison_pill.set()
        for thread in aws_ec2_resource.threadList:
          aws_ec2_resource.syslogger.info("Waiting for %s to finish..." %(thread.name))
          thread.join()
        sl_bfd_ha.syslogger.info("Unregistering SL-API services...")    
        sl_bfd_ha.bfd_regop(sl_common_types_pb2.SL_REGOP_UNREGISTER)
        sl_bfd_ha.poison_pill.set()
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
        self.setup_debug_logger()
        self.debug = False


    def toggle_debug(self, enable):
        """Enable/disable debug logging
           :param enable: Enable/Disable flag
           :type enable: int
        """
        if enable:
            self.debug = True
            self.logger.propagate = True
        else:
            self.debug = False
            self.logger.propagate = False

    def setup_debug_logger(self):
        """Setup the debug logger to throw debugs to stdout/stderr
        """

        logger = logging.getLogger('DebugHaAppLogger')
        if not len(logger.handlers):
            logger.setLevel(logging.DEBUG)
            # create console handler and set level to debug
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        self.logger = logger


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
            MAX_SIZE = 1024 * 1024
            LOG_PATH = "/var/log/ha_app_bkp.log"
            handler = logging.handlers.RotatingFileHandler(
                LOG_PATH, maxBytes=MAX_SIZE, backupCount=1)
            handler.formatter = formatter
            logger.addHandler(handler)

        self.syslogger = logger



class AWSClient(BaseLogger):


    def __init__(self,
                 syslog_file=None,
                 syslog_server=None,
                 syslog_port=None,
                 endpoint_url=None):

        super(AWSClient, self).__init__(syslog_file=syslog_file,
                                        syslog_server=syslog_server,
                                        syslog_port=syslog_port)
        self.metadata_url_latest=AWS_METADATA_URL_LATEST
        self.endpoint_url = endpoint_url
        self.exit = False
        self.poison_pill= Event()
        self.token_header=""
        self.start_time=datetime.datetime.now()
        self.setup_ec2_client()
        for fn in [self.setup_ec2_client]:
            thread = threading.Thread(target=fn, args=())
            self.threadList.append(thread)
            thread.daemon = True                            # Daemonize thread
            thread.start()                                  # Start the execution



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


    def fetch_temp_credentials(self):
        if self.token_header != "":
            try:
                response = requests.get(self.metadata_url_latest+"/meta-data/iam/security-credentials/ec2access", headers=self.token_header)
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
            time_elapsed_hours = (time_elapsed.total_seconds/3600)

            if (time_elapsed_hours >= 1) or (set_up):
                if not set_up:
                    self.syslogger.info("Time elapsed, refreshing temporary credentials")
                self.generate_token()
                self.fetch_temp_credentials()
                self.fetch_instance_region()
                self.fetch_self_instance_id()
                self.setup_boto_resource()
                if not self.exit:
                    self.start_time = datetime.datetime.now()
                    set_up=False
                else:
                    self.syslogger.info("Failed to set up AWS client resource. Will try again in some time...")
            else:
                self.syslogger.info("Credentials should still be valid, will check again in 15 mins..")
                while not self.poison_pill.is_set():
                    poisoned = self.poison_pill.wait(900) # Sleep for 15 mins before checking validity of credentials again

                if poisoned:
                    self.syslogger.info("Received poison pill, terminating setup_ec2_client thread...")
                    return {"status": "error", "output": "Received poison pill, terminating setup_ec2_client thread", "resource": None}
                else:
                    self.syslogger.info("Completed 15 mins, checking credentials again")


            if not self.exit:
                return {"status": "success", "output": "EC2 resource client created", "resource": self.resource}
            else:
                return {"status": "error", "output": "Failed to create EC2 resource client", "resource": None}






class SLHaBfd(BaseLogger):


    def __init__(self,
                 syslog_file=None,
                 syslog_server=None,
                 syslog_port=None,
                 grpc_server_ip="127.0.0.1",
                 grpc_server_port=57777,
                 config_json=None,
                 aws_resource=None):

        super(SLHaBfd, self).__init__(syslog_file=syslog_file,
                                      syslog_server=syslog_server,
                                      syslog_port=syslog_port)


        if aws_resource is None:
            self.syslogger.info("AWS resource client not provided, aborting...")
            self.exit = True
            return

        if config_json is None:
            self.syslogger.info("Input json config file not provided, aborting...")
            self.exit = True 
            return


        self.syslogger.info("Using GRPC Server IP(%s) Port(%s)" %(grpc_server_ip, grpc_server_port))
       
        # Create the channel for gRPC.
        self.channel = grpc.insecure_channel(str(grpc_server_ip)+":"+
                                                   str(grpc_server_port))
        self.poison_pill= Event()
        # Spawn a thread to Initialize the client and listen on notifications
        # The thread will run in the background
        self.global_init(self.channel)


        # Create the SL-BFD gRPC stub and register
        self.stub = sl_bfd_ipv4_pb2_grpc.SLBfdv4OperStub(self.channel)
        self.bfd_regop(sl_common_types_pb2.SL_REGOP_REGISTER)
        self.bfd_regop(sl_common_types_pb2.SL_REGOP_EOF)

        try:
            for bfd_session in config_json["config"]["bfd_sessions"]:
                bfd_session["bfd_oper"] = sl_common_types_pb2.SL_OBJOP_UPDATE
                self.bfd_op(**bfd_session)
        
        except Exception as e:
            self.syslogger.info("Failed to set up BFD sessions. Error: "+str(e))
            self.exit = True


        for fn in [self.bfd_notifications]:
            thread = threading.Thread(target=fn, args=())
            self.threadList.append(thread)
            thread.daemon = True                            # Daemonize thread
            thread.start()                                  # Start the execution


    
    def bfd_regop(self, bfd_regop):
        

        bfdRegMsg = sl_bfd_common_pb2.SLBfdRegMsg()
        bfdRegMsg.Oper = bfd_regop

        #
        # Make an RPC call
        #
        Timeout = 10 # Seconds
        response = self.stub.SLBfdv4RegOp(bfdRegMsg, Timeout)
        self.syslogger.info(response)

        #
        # Check the received result from the Server
        #
        try:
            if (response.StatusSummary.Status ==
                sl_common_types_pb2.SLErrorStatus.SL_SUCCESS):
                self.syslogger.info("BFD %s Success!" %(
                    list(sl_common_types_pb2.SLRegOp.keys())[oper]))
            else:
                self.syslogger.info("Error code for BFD %s is 0x%x! Response:" % (
                    list(sl_common_types_pb2.SLRegOp.keys())[oper],
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


    def bfd_op(self, 
               bfd_oper=None,
               session_type=None,
               intf_name=None,
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
        elif session_type == "MULTI_HOP":
            bfdv4session.Key.Type = sl_bfd_common_pb2.SLBfdType.SL_BFD_MULTI_HOP

        bfdv4session.Key.VrfName = vrf_name
        bfdv4session.Key.Interface.Name = intf_name
        bfdv4session.Key.NbrAddr = int(ipaddress.ip_address(neigh_ip))
        bfdv4session.Config.DesiredTxIntUsec = int(bfd_desired_tx_int_usec)
        bfdv4session.Config.DetectMultiplier = int(detect_multiplier)


        bfdv4Msg = sl_bfd_ipv4_pb2.SLBfdv4Msg()
        bfdv4Msg.Oper = bfd_oper

        bfdv4sessions = []
        bfdv4sessions.append(bfdv4session)
        bfdv4Msg.Sessions.extend(bfdv4sessions)

        response = self.stub.SLBfdv4SessionOp(bfdv4Msg, Timeout)

        self.syslogger.info(response)

        # bfdGetMsg = sl_bfd_common_pb2.SLBfdGetMsg()

        # response = self.stub.SLBfdv4Get(bfdGetMsg, Timeout)
        # self.syslogger.info(response)


        # response = self.stub.SLBfdv4GetStats(bfdGetMsg, Timeout)
        # self.syslogger.info(response)

        # For each neighbor set up the zeroMQ client/server connection



    def bfd_notifications(self):
        bfd_get_notif_msg = sl_bfd_common_pb2.SLBfdGetNotifMsg()
        #Timeout = 3600*24*365

        #instance_id=INSTANCE_ID
        try:
            while True:
                self.syslogger.info("Starting listener for BFD events")
                # Set Timeout if needed
                for response in self.stub.SLBfdv4GetNotifStream(bfd_get_notif_msg):
                    if self.poison_pill.is_set():
                        self.syslogger.info("Poison Pill received, terminating BFD notifications thread")
                        return

                    self.syslogger.info(response)
                    response_dict = json_format.MessageToDict(response)
                    if response_dict['Session']['State']['Status'] == 'SL_BFD_SESSION_DOWN':
                       self.syslogger.info("Peer is down, check current HA state and perform action...")
         

                       # instance = resource.Instance(instance_id)
                       # instance.network_interfaces[2].assign_private_ip_addresses(AllowReassignment=True, PrivateIpAddresses=['172.31.105.10'])
                       # self.syslogger.info("Assigned Secondary IP address to local instance interface")
                       # aws_call_event = True 
                       # aws_call_time = datetime.datetime.now()
                       # aws_call_time_elapsed_intf = aws_call_time - interface_time
                       # aws_call_time_elapsed_bfd = aws_call_time - bfd_time
                       # print("AWS call finished post Interface event of peer")
                       # print(aws_call_time.strftime('%Y/%m/%d %H:%M:%S.%f')[:-3])
                       # print("Time Elapsed post intf event in milliseconds")
                       # print(int(aws_call_time_elapsed_intf.total_seconds() * 1000))
                       # print("Time Elapsed post bfd event in milliseconds")
                       # print(int(aws_call_time_elapsed_bfd.total_seconds() * 1000))
                       # aws_call_event= False
                       # bfd_event = False
                       # interface_event = False


        except Exception as e:
            self.syslogger.info("Exception occured while listening to BFD notifications")
            self.syslogger.info(e)



    def client_init(self, stub, event):
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

        while True:
            # This for loop will never end unless the server closes the session
            # Set Timeout later if needed
            for response in stub.SLGlobalInitNotif(init_msg):
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
                        # Any thread waiting on this event can proceed
                        event.set()
                    else:
                        self.syslogger.info("client init error code 0x%x", response.ErrStatus.Status)
                        return
                elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_HEARTBEAT:
                    self.syslogger.info("Received HeartBeat")
                elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_ERROR:
                    if (sl_common_types_pb2.SLErrorStatus.SL_NOTIF_TERM ==
                            response.ErrStatus.Status):
                        self.syslogger.info("Received notice to terminate. Client Takeover?")
                        return
                    else:
                        self.syslogger.info("Error not handled:", response)
                else:
                    self.syslogger.info("client init unrecognized response %d", response.EventType)
                    return



    def global_thread(self, stub, event):
        self.syslogger.info("Global thread spawned")

        # Initialize the GRPC session. This function should never return
        self.client_init(stub, event)

        self.syslogger.info("global_thread: exiting unexpectedly")
        # If this session is lost, then most likely the server restarted
        # Typically this is handled by reconnecting to the server. For now, exit()
        return

    #
    # Spawn a thread for global events
    #
    def global_init(self,channel):
        # Create the gRPC stub.
        stub = sl_global_pb2_grpc.SLGlobalStub(channel)

        # Create a thread sync event. This will be used to order thread execution
        event = threading.Event()

        # The main reason we spawn a thread here, is that we dedicate a GRPC
        # channel to listen on Global asynchronous events/notifications.
        # This thread will be handling these event notifications.
        self.global_thread = threading.Thread(target = self.global_thread, args=(stub, event))
        self.global_thread.daemon = True
        self.global_thread.start()

        # Wait for the spawned thread before proceeding
        event.wait()

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
            return






#
# Setup the GRPC channel with the server, and issue RPCs
#
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config-file', dest='config_file', default=None,
                    help='Specify path to the json config file for HA App')

    argobj= parser.parse_args()
    base_logger = BaseLogger()

    if argobj.config_file is None:
        base_logger.syslogger.info("No Input config provided, bailing out.... Please provide a compatible json input file")
        sys.exit(1)

    # Read and load the input config.json file
    try:
        with open(argobj.config_file, 'r') as json_config_fd:
            json_config = json.load(json_config_fd)
    except Exception as e:
        base_logger.syslogger.info("Failed to load config file. Aborting...")
        sys.exit(1)

    if "ec2_private_endpoint_url" in json_config["config"]:
        endpoint_url = json_config["config"]["ec2_private_endpoint_url"]
    else:
        endpoint_url = "ec2.us-west-2.amazonaws.com"

    aws_ec2_resource = AWSClient(endpoint_url)

    
    if aws_ec2_resource["status"] == "error":
        base_logger.syslogger.info("Failed to create AWS client resource. Aborting...")
        sys.exit(1)

    

    if "syslog_file" in json_config["config"]:
        syslog_file = json_config["config"]["syslog_file"]
    else:
        syslog_file = None 

    if ("syslog_server" in json_config["config"]) and ("syslog_port" in json_config["config"]):
        syslog_server = json_config["config"]["syslog_server"]
        syslog_port = json_config["config"]["syslog_port"]
    else:
        syslog_server = None
        syslog_port = None

 
    if "grpc_server" in json_config["config"]:
        grpc_server = json_config["config"]["grpc_server"]
    else:
        base_logger.syslogger.info("gRPC server not specified in input config file, defaulting to 127.0.0.1")
        grpc_server ="127.0.0.1"

    if "grpc_port" in json_config["config"]:
        grpc_port = json_config["config"]["grpc_port"]
    else:
        base_logger.syslogger.info("gRPC port not specified in input config file, defaulting to 57777")
        grpc_server =57777
    
    # Set up the SLBFD object

    sl_bfd_ha =  SLHaBfd(syslog_file=syslog_file,
                         syslog_server=syslog_server,
                         syslog_port=syslog_port,
                         grpc_server_ip=grpc_server,
                         grpc_server_port=grpc_port,
                         config_json=json_config,
                         aws_resource=aws_ec2_resource)


    # Register our handler for keyboard interrupt and termination signals
    signal.signal(signal.SIGINT, partial(handler, sl_interface, sl_bfd_rtr1, sl_bfd_rtr2 ))
    signal.signal(signal.SIGTERM, partial(handler, sl_interface, sl_bfd_rtr1, sl_bfd_rtr2))

    # The process main thread does nothing but wait for signals
    signal.pause() 

    # RPC EOF to cleanup any previous stale BFD sessions 
    #bfd_regop(channel, sl_common_types_pb2.SL_REGOP_EOF)

    sys.exit(0)
