#
# Copyright (c) 2016 by cisco Systems, Inc. 
# All rights reserved.
#

# Standard python libs
import ipaddress
import os
import sys
import threading
import pdb
from functools import partial

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
import datetime
interface_event=False
bfd_event=False
aws_call_event=False
interface_time=datetime.datetime.now()
bfd_time=datetime.datetime.now()
aws_call_time=datetime.datetime.now()

#!/usr/bin/env python3
import boto3
import os
import requests
import pdb
import signal

headers = {
    'X-aws-ec2-metadata-token-ttl-seconds': '21600',
}

response = requests.put('http://169.254.169.254/latest/api/token', headers=headers)


headers = {
    'X-aws-ec2-metadata-token': response.text,
}

response = requests.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2access', headers=headers)

ACCESS_KEY=response.json()["AccessKeyId"]
SECRET_KEY=response.json()["SecretAccessKey"]
SESSION_TOKEN=response.json()["Token"]

response = requests.get("http://169.254.169.254/latest/meta-data/placement/region", headers=headers)
REGION_NAME=response.text

response = requests.get("http://169.254.169.254/latest/meta-data/instance-id", headers=headers)
#INSTANCE_ID = response.text
INSTANCE_ID='i-092b5318d504748cd'
PEER_INSTANCE_ID= 'i-0440aeae55f8166f1'

client = boto3.client(
    service_name='ec2',
    endpoint_url='https://vpce-0786bfdf8aad8840c-vacmlroq-us-west-2a.ec2.us-west-2.vpce.amazonaws.com',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
    region_name=REGION_NAME
    )

resource = boto3.resource(
    service_name='ec2',
    endpoint_url='https://vpce-0786bfdf8aad8840c-vacmlroq-us-west-2a.ec2.us-west-2.vpce.amazonaws.com',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
    region_name=REGION_NAME
    )


instance = resource.Instance(PEER_INSTANCE_ID)
instance.network_interfaces[2].assign_private_ip_addresses(AllowReassignment=True, PrivateIpAddresses=['172.31.105.10'])

# Utilities

# gRPC libs
import grpc


#
# Get the GRPC Server IP address and port number
#
def get_server_ip_port():
    # Get GRPC Server's IP from the environment
    if 'SERVER_IP' not in os.environ.keys():
        print("Need to set the SERVER_IP env variable e.g.")
        print("export SERVER_IP='10.30.110.214'")
        os._exit(0)

    # Get GRPC Server's Port from the environment
    if 'SERVER_PORT' not in os.environ.keys():
        print("Need to set the SERVER_PORT env variable e.g.")
        print("export SERVER_PORT='57777'")
        os._exit(0)

    return (os.environ['SERVER_IP'], int(os.environ['SERVER_PORT']))


#
# Client Init: Initialize client session
#    stub: GRPC stub
#
def client_init(stub, event):
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
    Timeout = 365*24*60*60 # Seconds

    # This for loop will never end unless the server closes the session
    for response in stub.SLGlobalInitNotif(init_msg, Timeout):
        if response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_VERSION:
            if (sl_common_types_pb2.SLErrorStatus.SL_SUCCESS ==
                    response.ErrStatus.Status) or \
                (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_CLEAR ==
                    response.ErrStatus.Status) or \
                (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_READY ==
                    response.ErrStatus.Status):
                print("Server Returned 0x%x, Version %d.%d.%d" %(
                    response.ErrStatus.Status,
                    response.InitRspMsg.MajorVer,
                    response.InitRspMsg.MinorVer,
                    response.InitRspMsg.SubVer))
                print("Successfully Initialized, connection established!")
                # Any thread waiting on this event can proceed
                event.set()
            else:
                print("client init error code 0x%x", response.ErrStatus.Status)
                os._exit(0)
        elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_HEARTBEAT:
            print("Received HeartBeat")
        elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_ERROR:
            if (sl_common_types_pb2.SLErrorStatus.SL_NOTIF_TERM ==
                    response.ErrStatus.Status):
                print("Received notice to terminate. Client Takeover?")
                os._exit(0)
            else:
                print("Error not handled:", response)
        else:
            print("client init unrecognized response %d", response.EventType)
            os._exit(0)



#
# Thread starting point
#
def global_thread(stub, event):
    print("Global thread spawned")

    # Initialize the GRPC session. This function should never return
    client_init(stub, event)

    print("global_thread: exiting unexpectedly")
    # If this session is lost, then most likely the server restarted
    # Typically this is handled by reconnecting to the server. For now, exit()
    os._exit(0)

#
# Spawn a thread for global events
#
def global_init(channel):
    # Create the gRPC stub.
    stub = sl_global_pb2_grpc.SLGlobalStub(channel)

    # Create a thread sync event. This will be used to order thread execution
    event = threading.Event()

    # The main reason we spawn a thread here, is that we dedicate a GRPC
    # channel to listen on Global asynchronous events/notifications.
    # This thread will be handling these event notifications.
    t = threading.Thread(target = global_thread, args=(stub, event))
    t.start()

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
        print("Max VRF Name Len     : %d" %(response.MaxVrfNameLength))
        print("Max Iface Name Len   : %d" %(response.MaxInterfaceNameLength))
        print("Max Paths per Entry  : %d" %(response.MaxPathsPerEntry))
        print("Max Prim per Entry   : %d" %(response.MaxPrimaryPathPerEntry))
        print("Max Bckup per Entry  : %d" %(response.MaxBackupPathPerEntry))
        print("Max Labels per Entry : %d" %(response.MaxMplsLabelsPerPath))
        print("Min Prim Path-id     : %d" %(response.MinPrimaryPathIdNum))
        print("Max Prim Path-id     : %d" %(response.MaxPrimaryPathIdNum))
        print("Min Bckup Path-id    : %d" %(response.MinBackupPathIdNum))
        print("Max Bckup Path-id    : %d" %(response.MaxBackupPathIdNum))
        print("Max Remote Bckup Addr: %d" %(response.MaxRemoteAddressNum))
    else:
        print("Globals response Error 0x%x" %(response.ErrStatus.Status))
        os._exit(0)





class SLInterface(object):

    def __init__(self, grpc_server_ip, grpc_server_port):


        #grpc_server_ip, grpc_server_port = self.get_server_ip_port()

        print("Using GRPC Server IP(%s) Port(%s)" %(grpc_server_ip, grpc_server_port))
       
 
        # Create the channel for gRPC.
        self.channel = grpc.insecure_channel(str(grpc_server_ip)+":"+
                                                   str(grpc_server_port))

        # Spawn a thread to Initialize the client and listen on notifications
        # The thread will run in the background
        self.global_init(self.channel)

        self.stub = sl_interface_pb2_grpc.SLInterfaceOperStub(self.channel)


        # Send an RPC for VRF registrations
        self.intf_register(sl_common_types_pb2.SL_REGOP_REGISTER)

        self.intf_register(sl_common_types_pb2.SL_REGOP_EOF)

        self.intf_enable_notif()

        self.intf_get_globals()

        self.intf_get_msg()


    def intf_register(self,oper):

        #if oper == sl_common_types_pb2.SL_REGOP_REGISTER:
            # Register the interface Client
            intfReg = sl_interface_pb2.SLInterfaceGlobalsRegMsg()
            intfReg.Oper = oper
            Timeout = 10
            response = self.stub.SLInterfaceGlobalsRegOp(intfReg, Timeout)
            print(response)


    def process_message(self, message_dict):

        event_type = message_dict["EventType"] 

        if event_type == "SL_INTERFACE_EVENT_TYPE_INTERFACE_INFO":
            interface = message_dict["Info"]["SLIfInfo"]["Name"]
            state = message_dict["Info"]["IfState"]
            # Do Something  


        
    def intf_listen_notifications(self):

        intf_getnotif_msg = sl_interface_pb2.SLInterfaceGetNotifMsg()

        Timeout = 3600*24*365

        try:
            while True:
                print("Starting listener for interface events")
                for response in self.stub.SLInterfaceGetNotifStream(intf_getnotif_msg, Timeout):
                    print(response)
                    response_dict = json_format.MessageToDict(response)
                    self.process_message(response_dict)                 
                    global interface_event
                    global interface_time
                    interface_event=True
                    interface_time=datetime.datetime.now()
                    print("Interface Event Occurred")
                    print(interface_time.strftime('%Y/%m/%d %H:%M:%S.%f')[:-3]) 
        except Exception as e:
            print("Exception occured while listening to Interface notifications")
            print(e)

    def intf_get_globals(self):
        intf_globalget = sl_interface_pb2.SLInterfaceGlobalsGetMsg()
   
        Timeout = 10 
        response = self.stub.SLInterfaceGlobalsGet(intf_globalget, Timeout)
        print(response)


    def intf_get_stats(self):
        intf_globalget = sl_interface_pb2.SLInterfaceGlobalsGetMsg()

        Timeout = 10
        response = self.stub.SLInterfaceGlobalsGetStats(intf_globalget, Timeout)
        print(response)

    def intf_enable_notif(self):

        intf_notif_op = sl_interface_pb2.SLInterfaceNotifMsg()

        intf_notif_op.Oper = sl_common_types_pb2.SL_NOTIFOP_ENABLE
        intf_name_list = []

        for intf_name in ['TenGigE0/0/0/2', 'TenGigE0/0/0/1']:
            interface = sl_common_types_pb2.SLInterface()
            interface.Name = intf_name
            intf_name_list.append(interface)

        intf_notif_op.Entries.extend(intf_name_list)
          
        Timeout = 10
        response = self.stub.SLInterfaceNotifOp(intf_notif_op, Timeout)
        print(response)
    
    def intf_get_msg(self):
        intf_get = sl_interface_pb2.SLInterfaceGetMsg()

        intf_get.EntriesCount = 5
        intf_get.GetNext = 0
        Timeout = 10
        response = self.stub.SLInterfaceGet(intf_get, Timeout)
        print(response)



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
        Timeout = 365*24*60*60 # Seconds
        #Timeout = 5

        while True:
            # This for loop will never end unless the server closes the session
            for response in stub.SLGlobalInitNotif(init_msg, Timeout):
                if response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_VERSION:
                    if (sl_common_types_pb2.SLErrorStatus.SL_SUCCESS ==
                            response.ErrStatus.Status) or \
                        (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_CLEAR ==
                            response.ErrStatus.Status) or \
                        (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_READY ==
                            response.ErrStatus.Status):
                        print("Server Returned 0x%x, Version %d.%d.%d" %(
                            response.ErrStatus.Status,
                            response.InitRspMsg.MajorVer,
                            response.InitRspMsg.MinorVer,
                            response.InitRspMsg.SubVer))
                        print("Successfully Initialized, connection established!")
                        # Any thread waiting on this event can proceed
                        event.set()
                    else:
                        print("client init error code 0x%x", response.ErrStatus.Status)
                        sys.exit(0)
                elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_HEARTBEAT:
                    print("Received HeartBeat")
                elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_ERROR:
                    if (sl_common_types_pb2.SLErrorStatus.SL_NOTIF_TERM ==
                            response.ErrStatus.Status):
                        print("Received notice to terminate. Client Takeover?")
                        sys.exit(0)
                    else:
                        print("Error not handled:", response)
                else:
                    print("client init unrecognized response %d", response.EventType)
                    sys.exit(0)



    def global_thread(self, stub, event):
        print("Global thread spawned")

        # Initialize the GRPC session. This function should never return
        self.client_init(stub, event)

        print("global_thread: exiting unexpectedly")
        # If this session is lost, then most likely the server restarted
        # Typically this is handled by reconnecting to the server. For now, exit()
        sys.exit(0)

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
            print("Max VRF Name Len     : %d" %(response.MaxVrfNameLength))
            print("Max Iface Name Len   : %d" %(response.MaxInterfaceNameLength))
            print("Max Paths per Entry  : %d" %(response.MaxPathsPerEntry))
            print("Max Prim per Entry   : %d" %(response.MaxPrimaryPathPerEntry))
            print("Max Bckup per Entry  : %d" %(response.MaxBackupPathPerEntry))
            print("Max Labels per Entry : %d" %(response.MaxMplsLabelsPerPath))
            print("Min Prim Path-id     : %d" %(response.MinPrimaryPathIdNum))
            print("Max Prim Path-id     : %d" %(response.MaxPrimaryPathIdNum))
            print("Min Bckup Path-id    : %d" %(response.MinBackupPathIdNum))
            print("Max Bckup Path-id    : %d" %(response.MaxBackupPathIdNum))
            print("Max Remote Bckup Addr: %d" %(response.MaxRemoteAddressNum))
        else:
            print("Globals response Error 0x%x" %(response.ErrStatus.Status))
            sys.exit(0)


    #
    # Get the GRPC Server IP address and port number
    #
    def get_server_ip_port(self):
        # Get GRPC Server's IP from the environment
        if 'SERVER_IP' not in list(os.environ.keys()):
            print("Need to set the SERVER_IP env variable e.g.")
            print("export SERVER_IP='10.30.110.214'")
            sys.exit(0)

        # Get GRPC Server's Port from the environment
        if 'SERVER_PORT' not in list(os.environ.keys()):
            print("Need to set the SERVER_PORT env variable e.g.")
            print("export SERVER_PORT='57777'")
            sys.exit(0)

        #return (os.environ['SERVER_IP'], int(os.environ['SERVER_PORT']))
        return('172.31.104.171', int('57777'))




class SLBfd(object):

    def __init__(self, rtr, neigh_ip0001, neigh_ip0002, grpc_server_ip, grpc_server_port, channel=None):

        self.neigh_ip0001 = neigh_ip0001
        self.neigh_ip0002 = neigh_ip0002 
        self.rtr=rtr


        #grpc_server_ip, grpc_server_port = self.get_server_ip_port()

        print("Using GRPC Server IP(%s) Port(%s)" %(grpc_server_ip, grpc_server_port))
       
 
        if channel is None:
            # Create the channel for gRPC.
            self.channel = grpc.insecure_channel(str(grpc_server_ip)+":"+
                                                       str(grpc_server_port))

        else:
            self.channel = channel
        # Spawn a thread to Initialize the client and listen on notifications
        # The thread will run in the background
        self.global_init(self.channel)

        # Create the gRPC stub
        self.stub = sl_bfd_ipv4_pb2_grpc.SLBfdv4OperStub(self.channel)
        self.bfd_regop(sl_common_types_pb2.SL_REGOP_REGISTER)
        self.bfd_regop(sl_common_types_pb2.SL_REGOP_EOF)


    def bfd_regop(self, bfd_regop):
        

        bfdRegMsg = sl_bfd_common_pb2.SLBfdRegMsg()
        bfdRegMsg.Oper = bfd_regop

        #
        # Make an RPC call
        #
        Timeout = 10 # Seconds
        response = self.stub.SLBfdv4RegOp(bfdRegMsg, Timeout)
        print(response)

        #
        # Check the received result from the Server
        #
        try:
            if (response.StatusSummary.Status ==
                sl_common_types_pb2.SLErrorStatus.SL_SUCCESS):
                print("BFD %s Success!" %(
                    list(sl_common_types_pb2.SLRegOp.keys())[oper]))
            else:
                print("Error code for BFD %s is 0x%x! Response:" % (
                    list(sl_common_types_pb2.SLRegOp.keys())[oper],
                    response.StatusSummary.Status
                ))
                print(response)
                # If we have partial failures within the batch, let's print them
                if (response.StatusSummary.Status ==
                    sl_common_types_pb2.SLErrorStatus.SL_SOME_ERR):
                    for result in response.Results:
                        print("Error code for %s is 0x%x" %(result.VrfName,
                            result.ErrStatus.Status
                        ))
                os._exit(0)
        except Exception as e:
            print(e)


    def bfd_op(self, bfd_oper):

        #bfdv4key.Type = sl_bfd_common_pb2.SLBfdType.SL_BFD_MULTI_HOP
        #bfdv4key.VrfName = "default"
        #bfdv4key.NbrAddr = int(ipaddress.ip_address("172.31.101.178"))
        #bfdv4key.SourceAddr = int(ipaddress.ip_address("172.31.103.242"))

        #bfdcommoncfg = sl_bfd_common_pb2.SLBfdConfigCommon()
        #bfdcommoncfg.DesiredTxIntUsec = int("50")
        #bfdcommoncfg.DetectMultiplier = int("3")
        #
        # Make an RPC call
        #
        Timeout = 10 # Seconds

        bfdv4session = sl_bfd_ipv4_pb2.SLBfdv4SessionCfg()
        bfdv4session.Key.Type = sl_bfd_common_pb2.SLBfdType.SL_BFD_SINGLE_HOP
        bfdv4session.Key.VrfName = "default"
        #bfdv4session.Key.SourceAddr = int(ipaddress.ip_address("172.31.101.178"))
        #bfdv4session.Key.NbrAddr = int(ipaddress.ip_address("172.31.103.242"))
        bfdv4session.Key.Interface.Name = "TenGigE0/0/0/1"
        bfdv4session.Key.NbrAddr = int(ipaddress.ip_address(self.neigh_ip0001))
        bfdv4session.Config.DesiredTxIntUsec = int("50000")
        bfdv4session.Config.DetectMultiplier = int("3")


        bfdv4Msg = sl_bfd_ipv4_pb2.SLBfdv4Msg()
        bfdv4Msg.Oper = bfd_oper

        bfdv4sessions = []
        bfdv4sessions.append(bfdv4session)


        bfdv4session = sl_bfd_ipv4_pb2.SLBfdv4SessionCfg()
        bfdv4session.Key.Type = sl_bfd_common_pb2.SLBfdType.SL_BFD_SINGLE_HOP
        bfdv4session.Key.VrfName = "default"
        #bfdv4session.Key.SourceAddr = int(ipaddress.ip_address("172.31.101.178"))
        #bfdv4session.Key.NbrAddr = int(ipaddress.ip_address("172.31.103.242"))
        bfdv4session.Key.Interface.Name = "TenGigE0/0/0/2"
        bfdv4session.Key.NbrAddr = int(ipaddress.ip_address(self.neigh_ip0002))
        bfdv4session.Config.DesiredTxIntUsec = int("50000")
        bfdv4session.Config.DetectMultiplier = int("3")

        bfdv4sessions.append(bfdv4session)
        bfdv4Msg.Sessions.extend(bfdv4sessions)

        response = self.stub.SLBfdv4SessionOp(bfdv4Msg, Timeout)

        print(response)

        bfdGetMsg = sl_bfd_common_pb2.SLBfdGetMsg()

        response = self.stub.SLBfdv4Get(bfdGetMsg, Timeout)
        print(response)


        response = self.stub.SLBfdv4GetStats(bfdGetMsg, Timeout)
        print(response)

        #pdb.set_trace()
        #bfdv4sessionget = sl_bfd_ipv4_pb2.SLBfdv4GetMsg()
        #bfdv4sessionget.EntriesCount = int("4")
        #response = stub.SLBfdv4SessionGet(bfdv4sessionget, Timeout)
        #print(response) 


    def bfd_notifications(self):
        if self.rtr == "rtr1":
            bfd_get_notif_msg = sl_bfd_common_pb2.SLBfdGetNotifMsg()
            Timeout = 3600*24*365

            instance_id=INSTANCE_ID
            try:
                while True:
                    print("Starting listener for BFD events")
                    for response in self.stub.SLBfdv4GetNotifStream(bfd_get_notif_msg, Timeout):
                        print(response)
                        response_dict = json_format.MessageToDict(response)
                        global interface_event
                        global bfd_event
                        global interface_time
                        global bfd_time 
                        global aws_call_time
                        global aws_call_event

                        if interface_event:
                            bfd_event = True
                            bfd_time = datetime.datetime.now()
                            bfd_time_elapsed= bfd_time -  interface_time
                            print("BFD Event Occurred post Interface event of peer in milliseconds")
                            print(bfd_time.strftime('%Y/%m/%d %H:%M:%S.%f')[:-3])
                            print("Time Elapsed")
                            print(int(bfd_time_elapsed.total_seconds() * 1000))
                        if response_dict['Session']['State']['Status'] == 'SL_BFD_SESSION_DOWN':
                           instance = resource.Instance(instance_id)
                           instance.network_interfaces[2].assign_private_ip_addresses(AllowReassignment=True, PrivateIpAddresses=['172.31.105.10'])
                           print("Assigned Secondary IP address to local instance interface")
                           aws_call_event = True 
                           aws_call_time = datetime.datetime.now()
                           aws_call_time_elapsed_intf = aws_call_time - interface_time
                           aws_call_time_elapsed_bfd = aws_call_time - bfd_time
                           print("AWS call finished post Interface event of peer")
                           print(aws_call_time.strftime('%Y/%m/%d %H:%M:%S.%f')[:-3])
                           print("Time Elapsed post intf event in milliseconds")
                           print(int(aws_call_time_elapsed_intf.total_seconds() * 1000))
                           print("Time Elapsed post bfd event in milliseconds")
                           print(int(aws_call_time_elapsed_bfd.total_seconds() * 1000))
                           aws_call_event= False
                           bfd_event = False
                           interface_event = False


            except Exception as e:
                print("Exception occured while listening to BFD notifications")
                print(e)



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
        Timeout = 365*24*60*60 # Seconds
        #Timeout = 5

        while True:
            # This for loop will never end unless the server closes the session
            for response in stub.SLGlobalInitNotif(init_msg, Timeout):
                if response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_VERSION:
                    if (sl_common_types_pb2.SLErrorStatus.SL_SUCCESS ==
                            response.ErrStatus.Status) or \
                        (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_CLEAR ==
                            response.ErrStatus.Status) or \
                        (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_READY ==
                            response.ErrStatus.Status):
                        print("Server Returned 0x%x, Version %d.%d.%d" %(
                            response.ErrStatus.Status,
                            response.InitRspMsg.MajorVer,
                            response.InitRspMsg.MinorVer,
                            response.InitRspMsg.SubVer))
                        print("Successfully Initialized, connection established!")
                        # Any thread waiting on this event can proceed
                        event.set()
                    else:
                        print("client init error code 0x%x", response.ErrStatus.Status)
                        sys.exit(0)
                elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_HEARTBEAT:
                    print("Received HeartBeat")
                elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_ERROR:
                    if (sl_common_types_pb2.SLErrorStatus.SL_NOTIF_TERM ==
                            response.ErrStatus.Status):
                        print("Received notice to terminate. Client Takeover?")
                        sys.exit(0)
                    else:
                        print("Error not handled:", response)
                else:
                    print("client init unrecognized response %d", response.EventType)
                    sys.exit(0)



    def global_thread(self, stub, event):
        print("Global thread spawned")

        # Initialize the GRPC session. This function should never return
        self.client_init(stub, event)

        print("global_thread: exiting unexpectedly")
        # If this session is lost, then most likely the server restarted
        # Typically this is handled by reconnecting to the server. For now, exit()
        sys.exit(0)

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
            print("Max VRF Name Len     : %d" %(response.MaxVrfNameLength))
            print("Max Iface Name Len   : %d" %(response.MaxInterfaceNameLength))
            print("Max Paths per Entry  : %d" %(response.MaxPathsPerEntry))
            print("Max Prim per Entry   : %d" %(response.MaxPrimaryPathPerEntry))
            print("Max Bckup per Entry  : %d" %(response.MaxBackupPathPerEntry))
            print("Max Labels per Entry : %d" %(response.MaxMplsLabelsPerPath))
            print("Min Prim Path-id     : %d" %(response.MinPrimaryPathIdNum))
            print("Max Prim Path-id     : %d" %(response.MaxPrimaryPathIdNum))
            print("Min Bckup Path-id    : %d" %(response.MinBackupPathIdNum))
            print("Max Bckup Path-id    : %d" %(response.MaxBackupPathIdNum))
            print("Max Remote Bckup Addr: %d" %(response.MaxRemoteAddressNum))
        else:
            print("Globals response Error 0x%x" %(response.ErrStatus.Status))
            sys.exit(0)


    #
    # Get the GRPC Server IP address and port number
    #
    def get_server_ip_port(self):
        # Get GRPC Server's IP from the environment
        if 'SERVER_IP' not in list(os.environ.keys()):
            print("Need to set the SERVER_IP env variable e.g.")
            print("export SERVER_IP='10.30.110.214'")
            sys.exit(0)

        # Get GRPC Server's Port from the environment
        if 'SERVER_PORT' not in list(os.environ.keys()):
            print("Need to set the SERVER_PORT env variable e.g.")
            print("export SERVER_PORT='57777'")
            sys.exit(0)

        return (os.environ['SERVER_IP'], int(os.environ['SERVER_PORT']))






EXIT_FLAG = False
#POSIX signal handler to ensure we shutdown cleanly
def handler(sl_interface, sl_bfd_rtr1, sl_bfd_rtr2, signum, frame):
    global EXIT_FLAG

    if not EXIT_FLAG:
        EXIT_FLAG = True
        print("Unregistering...")
        sl_interface.intf_register(sl_common_types_pb2.SL_REGOP_UNREGISTER)
        sl_bfd_rtr1.bfd_regop(sl_common_types_pb2.SL_REGOP_UNREGISTER)
        sl_bfd_rtr2.bfd_regop(sl_common_types_pb2.SL_REGOP_UNREGISTER)

       # Exit and Kill any running GRPC threads.
        os._exit(0)



#
# Setup the GRPC channel with the server, and issue RPCs
#
if __name__ == '__main__':

    # Create SLInterface object to setup netconf and gRPC connections, and configure active path,
    # before listening for interface events

    sl_interface = SLInterface("172.31.104.171", "57777")


    # This thread will be handling Interface event notifications.
    sl_interface.interface_listener = threading.Thread(target = sl_interface.intf_listen_notifications)
    sl_interface.interface_listener.daemon = True
    sl_interface.interface_listener.start()


    sl_bfd_rtr1 = SLBfd("rtr1", "172.31.101.101", "172.31.105.206", "172.31.104.9", "57777", channel=None)
    sl_bfd_rtr2 = SLBfd("rtr2", "172.31.101.170", "172.31.105.91", "172.31.104.171", "57777", channel=sl_interface.channel)

    sl_bfd_rtr1.bfd_op(sl_common_types_pb2.SL_OBJOP_ADD)
    sl_bfd_rtr2.bfd_op(sl_common_types_pb2.SL_OBJOP_ADD)

    sl_bfd_rtr1.bfd_listener_rtr1= threading.Thread(target = sl_bfd_rtr1.bfd_notifications)
    sl_bfd_rtr1.bfd_listener_rtr1.daemon =  True
    sl_bfd_rtr1.bfd_listener_rtr1.start()

    interface_event = False


    
        # Register our handler for keyboard interrupt and termination signals
    signal.signal(signal.SIGINT, partial(handler, sl_interface, sl_bfd_rtr1, sl_bfd_rtr2 ))
    signal.signal(signal.SIGTERM, partial(handler, sl_interface, sl_bfd_rtr1, sl_bfd_rtr2))

    # The process main thread does nothing but wait for signals
    signal.pause() 

    # RPC EOF to cleanup any previous stale BFD sessions 
    #bfd_regop(channel, sl_common_types_pb2.SL_REGOP_EOF)

    sys.exit(0)
