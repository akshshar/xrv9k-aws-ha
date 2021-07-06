#!/usr/bin/env python

import sys
sys.path.append('/pkg/bin')
from ztp_helper import ZtpHelpers

import os, posixpath, subprocess
import time, json
import threading, tempfile
from urlparse import urlparse
import signal, argparse
from functools import partial

import logging, logging.handlers
logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)


from ctypes import cdll
libc = cdll.LoadLibrary('libc.so.6')
_setns = libc.setns
CLONE_NEWNET = 0x40000000


class ExrSystemHelper(ZtpHelpers):

    def __init__(self,
                 syslog_file=None,
                 syslog_server=None,
                 syslog_port=None):

        super(ExrSystemHelper, self).__init__(syslog_file=syslog_file,
                                             syslog_server=syslog_server,
                                             syslog_port=syslog_port)

        self.root_lr_user = "ztp-user"
        standby_status = self.is_ha_setup()
        if standby_status["status"] == "success":
            if not standby_status["output"]:
                self.syslogger.info("Standby RP not present")
                self.ha_setup = False
            else:
                self.syslogger.info("Standby RP is present")
                self.ha_setup = True
        else:
                self.syslogger.info("Failed to get standby status, bailing out")
                self.exit = True


        # Am I the active RP?
        check_active_rp = self.is_active_rp()

        if check_active_rp["status"] == "success":
            if check_active_rp["output"]:
                self.active_rp = True
                self.syslogger.info("Running on active RP")
            else:
                self.active_rp = False
                self.syslogger.info("Not running on active RP")
        else:
            self.syslogger.info("Failed to check current RP node's state")
            self.exit =  True


        # Fetch and store the xrnns ip addresses of XR LXC on active and standby
        xrnns_ips = self.get_xr_ip()

        if xrnns_ips["status"] == "success":
            self.active_xr_ip = xrnns_ips["output"]["active_xr_ip"]
            self.standby_xr_ip = xrnns_ips["output"]["standby_xr_ip"]
        else:
            self.syslogger.info("Failed to fetch the xrnns ips of the XR LXCs on active/standby RPs")
            self.exit =  True

        self.exit = False



    def valid_path(self, file_path):
        return os.path.isfile(file_path)

    def run_bash(self, cmd=None, vrf="global-vrf", pid=1):
        """User defined method in Child Class
           Wrapper method for basic subprocess.Popen to execute
           bash commands on IOS-XR.
           :param cmd: bash command to be executed in XR linux shell.
           :type cmd: str

           :return: Return a dictionary with status and output
                    { 'status': '0 or non-zero',
                      'output': 'output from bash cmd' }
           :rtype: dict
        """

        with open(self.get_netns_path(nsname=vrf,nspid=pid)) as fd:
            self.setns(fd, CLONE_NEWNET)

            if self.debug:
                self.logger.debug("bash cmd being run: "+cmd)
            ## In XR the default shell is bash, hence the name
            if cmd is not None:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                out, err = process.communicate()
                if self.debug:
                    self.logger.debug("output: "+out)
                    self.logger.debug("error: "+err)
            else:
                self.syslogger.info("No bash command provided")
                return {"status" : 1, "output" : "", "error" : "No bash command provided"}

            status = process.returncode

            return {"status" : status, "output" : out, "error" : err}


    def is_active_rp(self):
        '''method to check if the node executing this daemon is the active RP
        '''
        # Get the current active RP node-name
        exec_cmd = "show redundancy summary"
        show_red_summary = self.xrcmd({"exec_cmd" : exec_cmd})

        if show_red_summary["status"] == "error":
             self.syslogger.info("Failed to get show redundancy summary output from XR")
             return {"status" : "error", "output" : "", "warning" : "Failed to get show redundancy summary output"}

        else:
            try:
                current_active_rp = show_red_summary["output"][2].split()[0]
            except Exception as e:
                self.syslogger.info("Failed to get Active RP from show redundancy summary output")
                return {"status" : "error", "output" : "", "warning" : "Failed to get Active RP, error: " + str(e)}

        cmd = "/sbin/ip netns exec xrnns /pkg/bin/node_list_generation -f MY"

        get_node_name = self.run_bash(cmd)
        my_node_name = ''

        if not get_node_name["status"]:
            my_node_name = get_node_name["output"]
        else:
            self.syslogger.info("Failed to get My Node Name. Output: "+str(get_node_name["output"])+", Error: "+str(get_node_name["output"]))


        if current_active_rp.strip() == my_node_name.strip():
            self.syslogger.info("I am the current RP, take action")
            return {"status" : "success", "output" : True, "warning" : ""}
        else:
            self.syslogger.info("I am not the current RP")
            return {"status" : "success", "output" : False, "warning" : ""}



    def get_peer_rp_ip(self):
        """User defined method in Child Class
           IOS-XR internally uses a private IP address space
           to reference linecards and RPs.

           This method uses XR internal binaries to fetch the
           internal IP address of the Peer RP in an HA setup.
           :param url: Complete url for config to be downloaded
           :param caption: Any reason to be specified when applying
                           config. Will show up in the output of:
                          "show configuration commit list detail"
           :type url: str
           :type caption: str
           :return: Return a dictionary with status and the peer RP IP
                    { 'status': 'error/success',
                      'peer_rp_ip': 'IP address of Peer RP' }
           :rtype: dict
        """
        cmd = "ip netns exec xrnns /pkg/bin/node_list_generation -f MY"
        bash_out = self.run_bash(cmd)
        if not bash_out["status"]:
            my_name = bash_out["output"]
        else:
            self.syslogger.info("Failed to get My Node Name")
            return {"status" : "error", "peer_rp_ip" : ""}

        cmd = "ip netns exec xrnns /pkg/bin/node_conversion -N " + str(my_name)
        bash_out = self.run_bash(cmd)
        if not bash_out["status"]:
            my_node_name = bash_out["output"].replace('\n', '')
        else:
            self.syslogger.info("Failed to convert My Node Name")
            return {"status" : "error", "peer_rp_ip" : ""}


        cmd = "ip netns exec xrnns /pkg/bin/node_list_generation -f ALL"
        bash_out = self.run_bash(cmd)

        if not bash_out["status"]:
            node_name_list = bash_out["output"].split()
        else:
            self.syslogger.info("Failed to get Node Name List")
            return {"status" : "error", "peer_rp_ip" : ""}


        for node in node_name_list:
            if "RP" in node:
                if my_node_name != node:
                    cmd="ip netns exec xrnns /pkg/bin/admin_nodeip_from_nodename -n " + str(node)
                    bash_out = self.run_bash(cmd)

                    if not bash_out["status"]:
                        return {"status" : "success", "peer_rp_ip" : bash_out["output"]}
                    else:
                        self.syslogger.info("Failed to get Peer RP IP")
                        return {"status" : "error", "peer_rp_ip" : ""}

        self.syslogger.info("There is no standby RP!")
        return {"status" : "error", "peer_rp_ip" : ""}



    def is_ha_setup(self):

        try:
            # Get the current active RP node-name
            exec_cmd = "show redundancy summary"
            show_red_summary = self.xrcmd({"exec_cmd" : exec_cmd})

            if show_red_summary["status"] == "error":
                self.syslogger.info("Failed to get show redundancy summary output from XR")
                return {"status" : "error", "output" : "", "warning" : "Failed to get show redundancy summary output"}
            else:
                try:
                    if "N/A" in show_red_summary["output"][2].split()[1]:
                        return {"status" : "success", "output": False} 
                    else:
                        return {"status" : "success", "output": True} 
                except Exception as e:
                    self.syslogger.info("Failed to extract standby status from show redundancy summary output")
                    return {"status" : "error", "output" : "Failed to get Active RP, error: " + str(e)}
        except Exception as e:
            self.syslogger.info("Failed to extract standby status from show redundancy summary output")
            return {"status" : "error", "output" : "Failed to get Active RP, error: " + str(e)}

    def scp_to_standby(self, dir_sync=False, src_path=None, dest_path=None, preserve_perms=False):
        """User defined method in Child Class
           Used to scp files from active to standby RP.

           leverages the get_peer_rp_ip() method above.
           Useful to keep active and standby in sync with files
           in the linux environment.
           :param dir_sync: Flag to sync directory using the recursive -r option for scp
           :param src_path: Source directory/file location on Active RP
           :param dest_path: Destination directory/file location on Standby RP
           :type src_path: str
           :type dest_path: str
           :return: Return a dictionary with status based on scp result.
                    { 'status': 'error/success' }
           :rtype: dict
        """
    
        if preserve_perms:
            scp_preserve_perm = "-p"
        else:
            scp_preserve_perm = ""

        if any([src_path, dest_path]) is None:
            self.syslogger.info("Incorrect File path\(s\)")
            return {"status" : "error"}

        standby_ip = self.get_peer_rp_ip()

        if standby_ip["status"] == "error":
            return {"status" : "error"}
        else:
            # First collect the mtu of eth-vf1 that connects to the standby RP in xrnns. Scp will likely stall at 2112 Kb because of the high
            # MTU setting on eth-vf1. This is a known issue in Linux kernels with scp for large files. We set the MTU of eth-vf1 to a lower
            # value = 1492 temporarily, initiate the transfer and change back the MTU.
            # See: http://stackoverflow.com/questions/11985008/sending-a-large-file-with-scp-to-a-certain-server-stalls-at-exactly-2112-kb

            # Grab original MTU of eth-vf1 in xrnns:
            cmd = "ip netns exec xrnns cat /sys/class/net/eth-vf1/mtu"
            mtu_value = self.run_bash(cmd)

            if mtu_value["status"]:
                self.syslogger.info("Failed to grab MTU of eth-vf1, aborting. Output: "+str(mtu_value["output"])+", Error: "+str(mtu_value["error"]))
            else:
                eth_vf1_mtu = mtu_value["output"]

            self.syslogger.info("Transferring "+str(src_path)+" from Active RP to standby location: " +str(dest_path))
            if dir_sync:
                self.syslogger.info("Copying entire directory and its subdirectories to standby")
                cmd = "ip netns exec xrnns ifconfig eth-vf1 mtu 1492 && ip netns exec xrnns scp "+str(scp_preserve_perm)+" -o ConnectTimeout=300 -r "+str(src_path)+ "/* root@" + str(standby_ip["peer_rp_ip"]) + ":" + str(dest_path)
            else:
                self.syslogger.info("Copying only the source file to target file location")
                cmd = "ip netns exec xrnns ifconfig eth-vf1 mtu 1492 && ip netns exec xrnns scp "+str(scp_preserve_perm)+" -o ConnectTimeout=300 "+str(src_path)+ " root@" + str(standby_ip["peer_rp_ip"]) + ":" + str(dest_path)
            bash_out = self.run_bash(cmd)

            if bash_out["status"]:
                self.syslogger.info("Failed to transfer file(s) to standby")
                return {"status" : "error"}
            else:
                # Reset MTU to original value
                cmd = "ip netns exec xrnns ifconfig eth-vf1 mtu "+str(eth_vf1_mtu)
                bash_out = self.run_bash(cmd)

                if bash_out["status"]:
                    self.syslogger.info("Failed to reset MTU on eth-vf1")
                    return {"status" : "error"}
                else:
                    return {"status" : "success"}


    def execute_cmd_on_standby(self, cmd=None):
        """User defined method in Child Class
           Used to execute bash commands on the standby RP
           and fetch the output over SSH.
           Leverages get_peer_rp_ip() and run_bash() methods above.
           :param cmd: bash command to execute on Standby RP
           :type cmd: str
           :return: Return a dictionary with status and output
                    { 'status': 'error/success',
                      'output': 'empty/output from bash cmd on standby' }
           :rtype: dict
        """

        if cmd is None:
            self.syslogger.info("No command specified")
            return {"status" : "error", "output" : ""}
        else:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write("#!/bin/bash\n%s" % cmd)
                f.flush()
                f.seek(0,0)

                standby_ip = self.get_peer_rp_ip()
                if standby_ip["status"] == "error":
                    return {"status" : "error", "output" : "", "error" : "Failed to get standby RP ip. No Standby?"}
                standby_cmd = "ip netns exec xrnns ssh root@"+str(standby_ip["peer_rp_ip"])+ " " + "\"$(< "+str(f.name)+")\""

                self.syslogger.info("Standby cmd: "+str(standby_cmd))

                bash_out = self.run_bash(standby_cmd)

                if bash_out["status"]:
                    self.syslogger.info("Failed to execute command on standby")
                    return {"status" : "error", "output" : "", "error": bash_out["error"]}
                else:
                    return {"status" : "success", "output": bash_out["output"], "error": ""}



    def admincmd(self, cmd=None):
        """Issue an admin exec cmd and obtain the output
           :param cmd: Dictionary representing the XR exec cmd
                       and response to potential prompts
                       { 'exec_cmd': '', 'prompt_response': '' }
           :type cmd: string 
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if cmd is None:
            return {"status" : "error", "output" : "No command specified"}

        status = "success"


        if self.debug:
            self.logger.debug("Received admin exec command request: \"%s\"" % cmd)

        cmd = "export AAA_USER="+self.root_lr_user+" && source /pkg/bin/ztp_helper.sh && echo -ne \""+cmd+"\\n \" | xrcmd \"admin\""

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        out, err = process.communicate()


        if process.returncode:
            status = "error"
            output = "Failed to get command output"
        else:
            output_list = []
            output = ""

            for line in out.splitlines():
                fixed_line= line.replace("\n", " ").strip()
                output_list.append(fixed_line)
                if "syntax error: expecting" in fixed_line:
                    status = "error"
                output = filter(None, output_list)    # Removing empty items

        if self.debug:
            self.logger.debug("Exec command output is %s" % output)

        return {"status" : status, "output" : output}

    def adminscp(self, src=None, dest=None):
        """Transfer a file from XR LXC to admin LXC
           :param src: Path of src file in XR to be 
                       transferred to admin shell
           :type src: string
           :param src: Path of destination file in admin shell 
           :type src: string
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """


        if src is None:
            return {"status" : "error", "output" : "src file path in XR not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in admin shell not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from XR LXC to admin LXC")


        result = self.admincmd(cmd="run scp root@"+self.active_xr_ip+":"+src+" "+dest)

        return {"status" : result["status"], "output" : result["output"]}


    def admin_to_xr_scp(self, src=None, dest=None):
        """Transfer a file from Admin LXC to active XR LXC
           :param src: Path of src file in Admin LXC to be 
                       transferred to active XR shell
           :type src: string
           :param src: Path of destination file in admin shell 
           :type src: string
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """


        if src is None:
            return {"status" : "error", "output" : "src file path in admin LXC not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in active XR shell not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from Admin LXC to XR LXC")


        result = self.admincmd(cmd="run scp "+src+" root@"+self.active_xr_ip+":"+dest)

        return {"status" : result["status"], "output" : result["output"]}


    def active_adminscp(self, src=None, dest=None):

        if src is None:
            return {"status" : "error", "output" : "src file path in XR not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in admin shell not specified"}


        if self.debug:
            self.logger.debug("Inside active_adminscp")

        # Get the active Admin LXC's xrnns ip
        result = self.get_admin_ip()

        if result["status"] == "success":
            active_admin_ip = result["output"]["active_admin_ip"]
        else:
            self.syslogger.info("Failed to get active RP's  admin xrnns ip")
            return {"status" : "error", "output" : ""}


        # First transfer the file to temp location in Admin LXC

        filename = posixpath.basename(src)

        result = self.adminscp(src=src, dest="/misc/scratch/"+tempfile)


        if result["status"] == "error":
            return {"status" : result["status"], "output" : result["output"]}
        else:
            result = self.admincmd(cmd="run scp /misc/scratch/"+tempfile+" root@"+active_admin_ip+":"+dest)

            # Remove tempfile from Admin shell

            self.admincmd(cmd="run rm -f /misc/scratch/"+tempfile)
            return {"status" : result["status"], "output" : result["output"]}


    def active_admin_to_xr_scp(self, src=None, dest=None):

        if src is None:
            return {"status" : "error", "output" : "src file path in active Admin shell not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in XR shell not specified"}


        if self.debug:
            self.logger.debug("Inside active_admin_to_xr_scp")

        # Get the active Admin LXC's xrnns ip
        result = self.get_admin_ip()

        if result["status"] == "success":
            active_admin_ip = result["output"]["active_admin_ip"]
        else:
            self.syslogger.info("Failed to get active RP's  admin xrnns ip")
            return {"status" : "error", "output" : ""}


        # First transfer the file to temp location in Admin LXC

        filename = posixpath.basename(src)

        result = self.admincmd(cmd="run scp root@"+active_admin_ip+":"+src+" /misc/scratch/"+tempfile)

        if result["status"] == "error":
            return {"status" : result["status"], "output" : result["output"]}
        else:
            result = self.admin_to_xr_scp(src="/misc/scratch/"+tempfile, dest=dest)

            # Remove tempfile from Admin shell

            self.admincmd(cmd="run rm -f /misc/scratch/"+tempfile)
            return {"status" : result["status"], "output" : result["output"]}

        

    def active_adminruncmd(self, cmd=None):

        if cmd is None:
            return {"status" : "error", "output" : "linux cmd not specified"}


        if self.debug:
            self.logger.debug("Received bash cmd: %s to run in shell of active RP's admin LXC" % cmd)


       # Get the active RP's admin LXC's xrnns ip:

        result = self.get_admin_ip()

        if result["status"] == "success":
            active_admin_ip = result["output"]["active_admin_ip"]
        else:
            self.syslogger.info("Failed to get the active admin xrnns ip")
            return {"status" : "error", "output" : ""}


        # Now run this command via the admin shell of the active RP

        result = self.admincmd(cmd="run ssh root@"+active_admin_ip+" "+cmd)

        return {"status" : result["status"], "output" : result["output"]}



    def hostcmd(self, cmd=None):
        """Issue a cmd in the host linux shell and obtain the output
           :param cmd: Dictionary representing the XR exec cmd
                       and response to potential prompts
                       { 'exec_cmd': '', 'prompt_response': '' }
           :type cmd: string 
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if cmd is None:
            return {"status" : "error", "output" : "No command specified"}


        if self.debug:
            self.logger.debug("Received host command request: \"%s\"" % cmd)


        result = self.admincmd(cmd="run ssh root@10.0.2.16 "+cmd)

        return {"status" : result["status"], "output" : result["output"]}



    def hostscp(self, src=None, dest=None):
        """Transfer a file from XR LXC to underlying host shell
           :param src: Path of src file in XR to be 
                       transferred to host shell
           :type src: string
           :param src: Path of destination file in host shell 
           :type src: string
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if src is None:
            return {"status" : "error", "output" : "src file path in XR not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in host shell not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from XR LXC to host shell")


        # First transfer the file to temp location in Admin LXC 

        filename = posixpath.basename(src)

        result = self.adminscp(src=src, dest="/misc/scratch/"+tempfile)


        if result["status"] == "error":
            return {"status" : result["status"], "output" : result["output"]}
        else:
            result = self.admincmd(cmd="run scp /misc/scratch/"+tempfile+" root@10.0.2.16:"+dest)

            # Remove tempfile from Admin shell

            self.admincmd(cmd="run rm -f /misc/scratch/"+tempfile)
            return {"status" : result["status"], "output" : result["output"]}


    def get_xr_ip(self):

        try:
            # First determine the currently allocated ip address for IOS-XR lxc in xrnns namespace
            # Show commands using Parent class helper method: xrcmd

            result = self.xrcmd({"exec_cmd" : "show platform vm"})

            # We first extract the XR-LXC IP from active and standby(if available) RPs:

            active_ip = ""
            standby_ip = ""

            for line in result["output"][2:]:
                row = filter(None, line.split(" "))
                if row[1] == "RP":
                    if "ACTIVE" in row[2]:
                        active_ip = row[6]
                    if "STANDBY" in row[2]:
                        standby_ip = row[6]

            return {"status" : "success",
                    "output" : {"active_xr_ip" : active_ip,
                                "standby_xr_ip" : standby_ip}
                   }

        except Exception as e:
            self.syslogger.info("Failed to fetch the  xr xrnns ips, Error:" +str(e))
            return {"status" : "error", "output" : str(e)}



    def get_admin_ip(self):
        active_admin_ip = ""
        standby_admin_ip = ""

        # First fetch the XR LXC xrnns ips for active and standby
 

        split_active_ip = self.active_xr_ip.split('.')
        split_active_ip[3] = '1'
        active_admin_ip = '.'.join(split_active_ip)
 
        if self.standby_xr_ip is not "":
            split_standby_ip = self.standby_xr_ip.split('.')
            split_standby_ip[3] = '1'
            standby_admin_ip = '.'.join(split_standby_ip)


        return {"status" : "success",
                "output" : {"active_admin_ip" : active_admin_ip,
                            "standby_admin_ip" : standby_admin_ip}
               }



    def standby_adminruncmd(self, cmd=None):

        if cmd is None:
            return {"status" : "error", "output" : "linux cmd not specified"}


        if self.debug:
            self.logger.debug("Received bash cmd: %s to run in shell of standby RP's admin LXC" % cmd)


       # Get the standby RP's admin LXC's xrnns ip:
    
        result = self.get_admin_ip()

        if result["status"] == "success":
            standby_admin_ip = result["output"]["standby_admin_ip"]
            if standby_admin_ip == "":
               self.syslogger.info("Did not receive a standby admin IP (no standby RP?), bailing out")
               return {"status" : "error", "output" : ""}
        else:
            self.syslogger.info("Failed to get the standby admin xrnns ip")
            return {"status" : "error", "output" : ""}


        # Now try to run this command via the admin LXC of the active RP

        result = self.admincmd(cmd="run ssh root@"+standby_admin_ip+" "+cmd)

        return {"status" : result["status"], "output" : result["output"]}





    def standby_adminscp(self, src=None, dest=None):

        if src is None:
            return {"status" : "error", "output" : "src file path in XR not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in standby admin shell not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from XR LXC to standby admin shell")


       # Get the standby RP's admin LXC's xrnns ip:

        result = self.get_admin_ip()

        if result["status"] == "success":
            standby_admin_ip = result["output"]["standby_admin_ip"]
            if standby_admin_ip == "":
               self.syslogger.info("Did not receive a standby admin IP (no standby RP?), bailing out")
               return {"status" : "error", "output" : ""}
        else:
            self.syslogger.info("Failed to get the standby admin xrnns ip")
            return {"status" : "error", "output" : ""}


        # First transfer the file to temp location in active Admin LXC 

        filename = posixpath.basename(src)

        result = self.adminscp(src=src, dest="/misc/scratch/"+tempfile)


        if result["status"] == "error":
            return {"status" : result["status"], "output" : result["output"]}
        else:
            result = self.admincmd(cmd="run scp /misc/scratch/"+tempfile+" root@"+standby_admin_ip+":"+dest)

            # Remove tempfile from Admin shell

            self.admincmd(cmd="run rm -f /misc/scratch/"+tempfile)
            return {"status" : result["status"], "output" : result["output"]}



    def standby_admin_to_xr_scp(self, src=None, dest=None):

        if src is None:
            return {"status" : "error", "output" : "src file path in standby Admin shell not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in XR shell not specified"}


        if self.debug:
            self.logger.debug("Inside standby_admin_to_xr_scp")

        # Get the standby Admin LXC's xrnns ip
        result = self.get_admin_ip()

        if result["status"] == "success":
            standby_admin_ip = result["output"]["standby_admin_ip"]
        else:
            self.syslogger.info("Failed to get standby RP's  admin xrnns ip")
            return {"status" : "error", "output" : ""}


        # First transfer the file to temp location in Admin LXC

        filename = posixpath.basename(src)

        result = self.admincmd(cmd="run scp root@"+standby_admin_ip+":"+src+" /misc/scratch/"+tempfile)

        if result["status"] == "error":
            return {"status" : result["status"], "output" : result["output"]}
        else:
            result = self.admin_to_xr_scp(src="/misc/scratch/"+tempfile, dest=dest)

            # Remove tempfile from Admin shell

            self.admincmd(cmd="run rm -f /misc/scratch/"+tempfile)
            return {"status" : result["status"], "output" : result["output"]}



    def standby_xrruncmd(self, cmd=None):
        """Issue a cmd in the standby xr linux shell and obtain the output
           :param cmd: String representing the linux cmd to run
           :type cmd: string 
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if cmd is None:
            return {"status" : "error", "output" : "No command specified"}


        if self.debug:
            self.logger.debug("Received standby xr run command request: \"%s\"" % cmd)


        # First fetch the XR LXC xrnns ips for active and standby

        if self.ha_setup:
            if self.standby_xr_ip is not "":
                cmd_run = self.run_bash("ssh root@"+self.standby_xr_ip+" "+cmd)
                if not cmd_run["status"]:
                    return {"status" : "success", "output" : cmd_run["output"]}
                else:
                    self.syslogger.info("Failed to run command on standby XR LXC shell")
                    return {"status" : "error", "output" : cmd_run["output"]}
            else:
                self.syslogger.info("No standby xr ip, (no standby RP?)")
                return {"status" : "error", "output" : cmd_run["output"]}

        else:
            self.syslogger.info("Not an HA setup, no standby - Bailing out")
            return {"status" : "error", "output" : ""}


    def standby_xrscp(self, src=None, dest=None):
        """Transfer a file from XR LXC to underlying host shell
           :param src: Path of src file in XR to be 
                       transferred to host shell
           :type src: string
           :param src: Path of destination file in host shell of standby RP 
           :type src: string
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if src is None:
            return {"status" : "error", "output" : "src file path in XR not specified"}

        if dest is None:
            return {"status" : "error", "output" : "dest file path in standby RP XR LXC shell not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from XR LXC in active to XR LXC on standby")

        # First fetch the XR LXC xrnns ips for active and standby

        if self.ha_setup:
            if self.standby_xr_ip is not "":
                cmd_run = self.run_bash("scp "+src+" root@"+self.standby_xr_ip+":"+dest)
                if not cmd_run["status"]:
                    return {"status" : "success", "output" : cmd_run["output"]}
                else:
                    self.syslogger.info("Failed to transfer file to standby XR LXC, output:"+cmd_run["output"]+", error:"+cmd_run["error"])
                    return {"status" : "error", "output" : cmd_run["error"]}
            else:
                self.syslogger.info("No standby xr ip, (no standby RP?)")
                return {"status" : "error", "output" : cmd_run["output"]}

        else:
            self.syslogger.info("Failed to fetch the  xr xrnns ips")
            return {"status" : "error", "output" : ""}


    def standby_to_active_xr_scp(self, src=None, dest=None):
        """Transfer a file from XR LXC to underlying host shell
           :param src: Path of src file in XR to be 
                       transferred to host shell
           :type src: string
           :param src: Path of destination file in host shell of standby RP 
           :type src: string
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if src is None:
            return {"status" : "error", "output" : "src file path in Standby XR not specified"}

        if dest is None:
            return {"status" : "error", "output" : "dest file path in Active XR LXC shell not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from Standby XR LXC to Active XR LXC")


        if self.ha_setup:
            if self.standby_xr_ip is not "":
                cmd_run = self.run_bash("scp root@"+self.standby_xr_ip+":"+src+" "+dest)
                if not cmd_run["status"]:
                    return {"status" : "success", "output" : cmd_run["output"]}
                else:
                    self.syslogger.info("Failed to transfer file from standby XR LXC, output:"+cmd_run["output"]+", error:"+cmd_run["error"])
                    return {"status" : "error", "output" : cmd_run["error"]}
            else:
                self.syslogger.info("No standby xr ip, (no standby RP?)")
                return {"status" : "error", "output" : cmd_run["output"]}

        else:
            self.syslogger.info("Failed to fetch the  xr xrnns ips")
            return {"status" : "error", "output" : ""}



    def active_hostcmd(self, cmd=None):
        """Issue a cmd in the host linux shell and obtain the output
           :param cmd: Dictionary representing the XR exec cmd
                       and response to potential prompts
                       { 'exec_cmd': '', 'prompt_response': '' }
           :type cmd: string 
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if cmd is None:
            return {"status" : "error", "output" : "No command specified"}

        if self.debug:
            self.logger.debug("Received host command request: \"%s\"" % cmd)


        result = self.active_adminruncmd(cmd="ssh root@10.0.2.16 "+cmd)

        return {"status" : result["status"], "output" : result["output"]}



    def active_hostscp(self, src=None, dest=None):
        """Transfer a file from XR LXC to underlying host shell
           :param src: Path of src file in XR to be 
                       transferred to host shell
           :type src: string
           :param src: Path of destination file in host shell of standby RP 
           :type src: string
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if src is None:
            return {"status" : "error", "output" : "src file path in XR not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in host shell not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from XR LXC to host shell")


        # First transfer the file to temp location in active Admin LXC 

        filename = posixpath.basename(src)

        result = self.active_adminscp(src=src, dest="/misc/scratch/"+tempfile)


        if result["status"] == "error":
            return {"status" : result["status"], "output" : result["output"]}
        else:
            result = self.active_adminruncmd(cmd="scp /misc/scratch/"+tempfile+" root@10.0.2.16:"+dest)

            # Remove tempfile from activey Admin shell

            self.active_adminruncmd(cmd="rm -f /misc/scratch/"+tempfile)
            return {"status" : result["status"], "output" : result["output"]}


    def active_host_to_xr_scp(self, src=None, dest=None):

        if src is None:
            return {"status" : "error", "output" : "src file path in active host not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in active XR-LXC not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from active host to active XR")


        # First transfer the file to temp location in active Admin LXC 

        filename = posixpath.basename(src)

        result = self.active_adminruncmd(cmd="scp root@10.0.2.16:"+src+" /misc/scratch/"+tempfile)

        if result["status"] == "error":
            return {"status" : result["status"], "output" : result["output"]}
        else:
            result = self.active_admin_to_xr_scp(src="/misc/scratch/"+tempfile, dest=dest)
            # Remove tempfile from active Admin shell

            self.active_adminruncmd(cmd="rm -f /misc/scratch/"+tempfile)
            return {"status" : result["status"], "output" : result["output"]}



    def standby_hostcmd(self, cmd=None):
        """Issue a cmd in the host linux shell and obtain the output
           :param cmd: Dictionary representing the XR exec cmd
                       and response to potential prompts
                       { 'exec_cmd': '', 'prompt_response': '' }
           :type cmd: string 
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if cmd is None:
            return {"status" : "error", "output" : "No command specified"}

        if self.debug:
            self.logger.debug("Received host command request: \"%s\"" % cmd)


        result = self.standby_adminruncmd(cmd="ssh root@10.0.2.16 "+cmd)

        return {"status" : result["status"], "output" : result["output"]}



    def standby_hostscp(self, src=None, dest=None):
        """Transfer a file from XR LXC to underlying host shell
           :param src: Path of src file in XR to be 
                       transferred to host shell
           :type src: string
           :param src: Path of destination file in host shell of standby RP 
           :type src: string
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': '' }
           :rtype: string
        """

        if src is None:
            return {"status" : "error", "output" : "src file path in XR not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in host shell not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from XR LXC to host shell")


        # First transfer the file to temp location in standby Admin LXC 

        filename = posixpath.basename(src)


        result = self.standby_adminscp(src=src, dest="/misc/scratch/"+tempfile)


        if result["status"] == "error":
            return {"status" : result["status"], "output" : result["output"]}
        else:
            result = self.standby_adminruncmd(cmd="scp /misc/scratch/"+tempfile+" root@10.0.2.16:"+dest)

            # Remove tempfile from Standby Admin shell

            self.standby_adminruncmd(cmd="rm -f /misc/scratch/"+tempfile)
            return {"status" : result["status"], "output" : result["output"]}



    def standby_host_to_xr_scp(self, src=None, dest=None):

        if src is None:
            return {"status" : "error", "output" : "src file path in standby host not specified"}


        if dest is None:
            return {"status" : "error", "output" : "dest file path in active XR-LXC not specified"}


        if self.debug:
            self.logger.debug("Received scp request to transfer file from standby host to active XR")


        # First transfer the file to temp location in standby Admin LXC 

        filename = posixpath.basename(src)


        result = self.standby_adminruncmd(cmd="scp root@10.0.2.16:"+src+" /misc/scratch/"+tempfile)

        if result["status"] == "error":
            return {"status" : result["status"], "output" : result["output"]}
        else:
            result = self.standby_admin_to_xr_scp(src="/misc/scratch/"+tempfile, dest=dest)
            # Remove tempfile from active Admin shell

            self.standby_adminruncmd(cmd="rm -f /misc/scratch/"+tempfile)
            return {"status" : result["status"], "output" : result["output"]}


    def reload_current_standby(self):
        # Get the current active RP node-name
        exec_cmd = "show redundancy summary"
        show_red_summary = self.xrcmd({"exec_cmd" : exec_cmd})

        if show_red_summary["status"] == "error":
             self.syslogger.info("Failed to get show redundancy summary output from XR")
             return {"status" : "error", "output" : "", "warning" : "Failed to get show redundancy summary output"}

        else:
            try:
                current_standby_rp = show_red_summary["output"][2].split()[1]
            except Exception as e:
                self.syslogger.info("Failed to get Standby RP from show redundancy summary output")
                return {"status" : "error", "output" : "", "warning" : "Failed to get Active RP, error: " + str(e)}

        # Reload standby RP
        result = self.admincmd(cmd="hw-module location "+str(current_standby_rp)+" reload noprompt")

        if result["status"] == "error":
            self.syslogger.info("Failed to reload Standby RP, please reload manually. Error: "+str(result["output"]))
        else:
            self.syslogger.info("Initiated Standby RP reload. Output: "+str(result["output"]))
        

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', action='append', dest='input_files',
                    help='Specify path of the file to be set up on Standby RP XR LXC')
    parser.add_argument('-d', '--directory', action='append', dest='input_directories',
                    help='Specify path of the directories to be set up on Standby RP XR LXC')
    parser.add_argument('-c', '--cmd', action='append', dest='standby_bash_cmds',
                    help='Specify the bash commands to be run on standby RP XR LXC')
    parser.add_argument('-a', '--active-admin-cmd', action='append', dest='active_admin_cmds',
                    help='Specify the bash commands to run on active RP admin LXC')
    parser.add_argument('-s', '--standby-admin-cmd', action='append', dest='standby_admin_cmds',
                    help='Specify the bash commands to run on standby RP admin LXC')
    parser.add_argument('-i', '--active-host-cmd', action='append', dest='active_host_cmds',
                    help='Specify the bash commands to run on active RP host')
    parser.add_argument('-j', '--standby-host-cmd', action='append', dest='standby_host_cmds',
                    help='Specify the bash commands to run on standby RP host')
    parser.add_argument('-r', '--standby-rp-reload', action='store_true', dest='standby_rp_reload',
                    help='Reload standby RP')
    parser.add_argument('-v', '--verbose', action='store_true',
                    help='Enable verbose logging')
    

    results = parser.parse_args()
    if results.verbose:
        logger.info("Starting verbose debugging")
        logging.basicConfig()
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)


    exr_system_helper = ExrSystemHelper()
    #Check if there is a standby RP on the system. If not, abort.

    standby_ip = exr_system_helper.get_peer_rp_ip()

    if standby_ip["status"] == "error":
        exr_system_helper.syslogger.info("No standby RP detected or failed to get standby RP xrnns ip. Aborting...")
        sys.exit(0)

    if results.input_files is None:
        exr_system_helper.syslogger.info("No input file provided, checking for directories to sync...")
    else:
        for filename in results.input_files:
            # Execute scp_to_standby for each file provided as input
            scp_output = exr_system_helper.scp_to_standby(src_path=os.path.abspath(filename), 
                                           dest_path=os.path.abspath(filename), 
                                           preserve_perms=True)
            if scp_output["status"] == "error":
                exr_system_helper.syslogger.info("Failed to set up file: "+str(os.path.abspath(filename))+" on the standby RP")
                sys.exit(1)
            else:
                exr_system_helper.syslogger.info("Successfully set up file: "+str(os.path.abspath(filename))+" on the standby RP")



    if results.input_directories is None:
        exr_system_helper.syslogger.info("No input directories provided...")
    else:
        for dirname in results.input_directories:
            # Execute scp_to_standby for each directory provided as input
            scp_output = exr_system_helper.scp_to_standby(dir_sync=True,
                                           src_path=os.path.abspath(dirname),
                                           dest_path=os.path.abspath(dirname),
                                           preserve_perms=True)
            if scp_output["status"] == "error":
                exr_system_helper.syslogger.info("Failed to set up directory: "+str(os.path.abspath(dirname))+" on the standby RP")
                sys.exit(1)
            else:                                 
                exr_system_helper.syslogger.info("Successfully set up directory: "+str(os.path.abspath(dirname))+" on the standby RP")


    if results.standby_bash_cmds is None:
        exr_system_helper.syslogger.info("No Standby RP bash commands provided...")
    else:
        for cmd in results.standby_bash_cmds:
            # Run execute_cmd_on_standby for each bash command provided as input
            standby_bash_cmd = exr_system_helper.execute_cmd_on_standby(cmd = cmd)
            
            if standby_bash_cmd["status"] == "error":
                exr_system_helper.syslogger.info("Failed to execute bash cmd: \""+str(cmd)+"\" on the standby RP. Output: "+str(standby_bash_cmd["output"])+". Error: "+str(standby_bash_cmd["error"]))
                sys.exit(1)
            else:
                exr_system_helper.syslogger.info("Successfully executed bash cmd: \""+str(cmd)+"\" on the standby RP. Output: "+str(standby_bash_cmd["output"]))
             

    if results.active_admin_cmds is None:
        exr_system_helper.syslogger.info("No Active RP admin bash commands provided...")
    else:
        for cmd in results.active_admin_cmds:
            # Run execute_cmd_on_standby for each bash command provided as input
            active_admin_bash_cmd = exr_system_helper.admincmd(cmd = cmd)

            if active_admin_bash_cmd["status"] == "error":
                exr_system_helper.syslogger.info("Failed to execute bash cmd: \""+str(cmd)+"\" on the Active RP admin LXC. Output: "+str(active_admin_bash_cmd["output"])+". Error: "+str(active_admin_bash_cmd["error"]))
                sys.exit(1)
            else:
                exr_system_helper.syslogger.info("Successfully executed bash cmd: \""+str(cmd)+"\" on the Active RP admin LXC. Output: "+str(active_admin_bash_cmd["output"]))



    if results.standby_admin_cmds is None:
        exr_system_helper.syslogger.info("No Standby RP bash commands provided...")
    else:
        for cmd in results.standby_admin_cmds:
            # Run execute_cmd_on_standby for each bash command provided as input
            standby_admin_bash_cmd = exr_system_helper.standby_adminruncmd(cmd = cmd)

            if standby_admin_bash_cmd["status"] == "error":
                exr_system_helper.syslogger.info("Failed to execute bash cmd: \""+str(cmd)+"\" on the standby RP admin LXC. Output: "+str(standby_admin_bash_cmd["output"])+". Error: "+str(standby_admin_bash_cmd["error"]))
                sys.exit(1)
            else:
                exr_system_helper.syslogger.info("Successfully executed bash cmd: \""+str(cmd)+"\" on the standby RP admin LXC. Output: "+str(standby_admin_bash_cmd["output"]))



    if results.active_host_cmds is None:
        exr_system_helper.syslogger.info("No active RP host commands provided...")
    else:
        for cmd in results.active_host_cmds:
            # Run execute_cmd_on_standby for each bash command provided as input
            active_host_bash_cmd = exr_system_helper.active_hostcmd(cmd = cmd)

            if active_host_bash_cmd["status"] == "error":
                exr_system_helper.syslogger.info("Failed to execute bash cmd: \""+str(cmd)+"\" on the Active RP host. Output: "+str(active_host_bash_cmd["output"])+". Error: "+str(active_host_bash_cmd["error"]))
                sys.exit(1)
            else:
                exr_system_helper.syslogger.info("Successfully executed bash cmd: \""+str(cmd)+"\" on the Active RP host. Output: "+str(active_host_bash_cmd["output"]))

    if results.standby_host_cmds is None:
        exr_system_helper.syslogger.info("No Standby RP bash commands provided...")
    else:
        for cmd in results.standby_host_cmds:
            # Run execute_cmd_on_standby for each bash command provided as input
            standby_host_bash_cmd = exr_system_helper.standby_hostcmd(cmd = cmd)

            if standby_host_bash_cmd["status"] == "error":
                exr_system_helper.syslogger.info("Failed to execute bash cmd: \""+str(cmd)+"\" on the standby RP host. Output: "+str(standby_host_bash_cmd["output"])+". Error: "+str(standby_host_bash_cmd["error"]))
                sys.exit(1)
            else:
                exr_system_helper.syslogger.info("Successfully executed bash cmd: \""+str(cmd)+"\" on the standby RP host. Output: "+str(standby_host_bash_cmd["output"]))


    if results.standby_rp_reload:
        exr_system_helper.syslogger.info("Reloading Standby RP....")
        exr_system_helper.reload_current_standby()

    exr_system_helper.syslogger.info("Done!")
    sys.exit(0)

