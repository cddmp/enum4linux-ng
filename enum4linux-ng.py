#!/usr/bin/python3

### DESIGN
# * Functions:
#       * return value is None/False     => error happened
#       * return value is empty [],{},"" => no error, nothing was returned
# * YAML/JSON:
#   * something is missing => was not part of the enumeration OR an error happened, check
#                               errors entry in JSON/YAML
### PYLINT
# pylint: disable=C0301
#
### FIXME
# FIXME: Not sure if the run_something stuff is too crappy,
# FIXME: equal output for users, groups and rid_cycling
# FIXME: services via 'net rpc service list -W bla -U % -I ip'
# FIXME: pylint
# even if the result is not processed by other functions
#
### CREDITS
# This tool is rewrite of Mark Lowe's enum4linux.pl (v0.8.3).
# Credits to him for creating the original tool. His tool was originally release
# under GPLv2 or later.
#
# Instead of calling polenum, I decided to integrate it in the code. I added comments
# to the affected functions.
# Credits to Wh1t3Fox for creating polenum.py. His tool was originally released
# under GPLv3. 
#
### LICENSE
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# you are not permitted to use this tool.
#
# In all other respects the GPL version 3 applies.

import argparse
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
from collections import OrderedDict
from time import gmtime, strftime, time
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5 import transport, samr
import ldap
import yaml

###############################################################################
# The following  mappings for nmblookup (nbtstat) status codes to human readable
# format is taken from nbtscan 1.5.1 "statusq.c".  This file in turn
# was derived from the Samba package which contains the following
# license:
#    Unix SMB/Netbios implementation
#    Version 1.9
#    Main SMB server routine
#    Copyright (C) Andrew Tridgell 1992-199
#
#    This program is free software; you can redistribute it and/or modif
#    it under the terms of the GNU General Public License as published b
#    the Free Software Foundation; either version 2 of the License, o
#    (at your option) any later version
#
#    This program is distributed in the hope that it will be useful
#    but WITHOUT ANY WARRANTY; without even the implied warranty o
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See th
#    GNU General Public License for more details
#
#    You should have received a copy of the GNU General Public Licens
#    along with this program; if not, write to the Free Softwar
#    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA

global_nbt_info = [
    ["__MSBROWSE__", "01", False, "Master Browser"],
    ["INet~Services", "1C", False, "IIS"],
    ["IS~", "00", True, "IIS"],
    ["", "00", True, "Workstation Service"],
    ["", "01", True, "Messenger Service"],
    ["", "03", True, "Messenger Service"],
    ["", "06", True, "RAS Server Service"],
    ["", "1F", True, "NetDDE Service"],
    ["", "20", True, "File Server Service"],
    ["", "21", True, "RAS Client Service"],
    ["", "22", True, "Microsoft Exchange Interchange(MSMail Connector)"],
    ["", "23", True, "Microsoft Exchange Store"],
    ["", "24", True, "Microsoft Exchange Directory"],
    ["", "30", True, "Modem Sharing Server Service"],
    ["", "31", True, "Modem Sharing Client Service"],
    ["", "43", True, "SMS Clients Remote Control"],
    ["", "44", True, "SMS Administrators Remote Control Tool"],
    ["", "45", True, "SMS Clients Remote Chat"],
    ["", "46", True, "SMS Clients Remote Transfer"],
    ["", "4C", True, "DEC Pathworks TCPIP service on Windows NT"],
    ["", "52", True, "DEC Pathworks TCPIP service on Windows NT"],
    ["", "87", True, "Microsoft Exchange MTA"],
    ["", "6A", True, "Microsoft Exchange IMC"],
    ["", "BE", True, "Network Monitor Agent"],
    ["", "BF", True, "Network Monitor Application"],
    ["", "03", True, "Messenger Service"],
    ["", "00", False, "Domain/Workgroup Name"],
    ["", "1B", True, "Domain Master Browser"],
    ["", "1C", False, "Domain Controllers"],
    ["", "1D", True, "Master Browser"],
    ["", "1E", False, "Browser Service Elections"],
    ["", "2B", True, "Lotus Notes Server Service"],
    ["IRISMULTICAST", "2F", False, "Lotus Notes"],
    ["IRISNAMESERVER", "33", False, "Lotus Notes"],
    ['Forte_$ND800ZA', "20", True, "DCA IrmaLan Gateway Server Service"]
]

# ACB (Account Control Block) contains flags an SAM account
global_acb_dict = {
        0x00000001: "Account Disabled",
        0x00000200: "Password not expired",
        0x00000400: "Account locked out",
        0x00020000: "Password expired",
        0x00000040: "Interdomain trust account",
        0x00000080: "Workstation trust account",
        0x00000100: "Server trust account",
        0x00002000: "Trusted for delegation"
        }

# Source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/d275ab19-10b0-40e0-94bb-45b7fc130025
global_domain_fields = {
        0x00000001: "DOMAIN_PASSWORD_COMPLEX",
        0x00000002: "DOMAIN_PASSWORD_NO_ANON_CHANGE",
        0x00000004: "DOMAIN_PASSWORD_NO_CLEAR_CHANGE",
        0x00000008: "DOMAIN_PASSWORD_LOCKOUT_ADMINS",
        0x00000010: "DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT",
        0x00000020: "DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE"
        }

global_deps = ["nmblookup", "net", "rpcclient", "smbclient"]
global_highest_rid = 50000
global_rid_ranges = "500-550,1000-1050"
global_known_usernames = "administrator,guest,krbtgt,domain admins,root,bin,none"

# global_verbose is the only global variable which should be written to
global_verbose = False

class Colors:
    reset = '\033[0m'
    red = '\033[91m'
    green = '\033[92m'
    blue = '\033[94m'

class Result:
    def __init__(self, retval, retmsg):
        self.retval = retval
        self.retmsg = retmsg

class Target:
    def __init__(self, host, workgroup, port=None, tls=None):
        self.host = host
        self.port = port
        self.workgroup = workgroup

class Credentials:
    def __init__(self, user, pw):
        self.user = user
        self.pw = pw

class Output:
    def __init__(self, out_file=None, out_file_type=None):
        self.out_file = out_file
        self.out_file_type = out_file_type
        self.out_dict = OrderedDict({"errors":{}})

    def update(self, content):
        errors_dict = self.out_dict["errors"]
        self.out_dict.update(content)
        if "errors" in content:
            errors = {**errors_dict, **content["errors"]}
            self.out_dict["errors"] = errors
            self.out_dict.move_to_end("errors")

        if self.out_file is not None:
            try:
                f = open(self.out_file, 'w')
                if self.out_file_type == "json":
                    f.write(json.dumps(self.out_dict, indent=4))
                elif self.out_file_type == "yaml":
                    f.write(yaml.dump(self.out_dict))
                f.close()
            except IOError as e:
                abort(1, f"An error happened trying go write to {self.out_file}. Exiting.")

    def as_dict(self):
        return self.out_dict

# For RID Cycling we need various params, RID Range and known_usernames are mandatory.
# enumerated_input is a dictionary which contains already enumerated input like "users,
# "groups", "machines" and/or a domain sid. By default enumerated_input is an empty dict
# and will be filled up during the tool run.
class RidCycleParams:
    def __init__(self, rid_ranges, known_usernames):
        self.rid_ranges = rid_ranges
        self.known_usernames = known_usernames
        self.enumerated_input = {}
        for key in ["users", "groups", "machines"]:
            if key not in self.enumerated_input:
                self.enumerated_input[key] = {}
        if "domain_sid" not in self.enumerated_input:
            self.enumerated_input["domain_sid"] = ""

def print_heading(text):
    output = f"|    {text}    |"
    length = len(output)
    print()
    print(" " + "="*(length-2))
    print(output)
    print(" " + "="*(length-2))

def print_success(msg):
    print(f"{Colors.green}[+] {msg + Colors.reset}")

def print_error(msg):
    print(f"{Colors.red}[-] {msg + Colors.reset}")

def print_info(msg):
    print(f"{Colors.blue}[*] {msg + Colors.reset}")

def print_verbose(msg):
    print(f"[V] {msg}")

# Helper function to print error and update output dictionary at the same time...
def process_error(msg, module_name, output_dict):
    print_error(msg)

    if not "errors" in output_dict:
        output_dict["errors"] = {}

    if not module_name in output_dict["errors"]:
        output_dict["errors"] = {module_name: []}

    output_dict["errors"][module_name] += [msg]
    return output_dict

def abort(code, msg):
    print_error(msg)
    sys.exit(code)

def run_nmblookup(host):
    '''
    Runs nmblookup (a NetBIOS over TCP/IP Client) in order to lookup NetBIOS names information.
    '''

    command = ["nmblookup", "-A", host]
    nmblookup_result = run(command, "Trying to get NetBIOS names information")

    if f"No reply from {host}" in nmblookup_result:
        return Result(None, "Can't get NetBIOS names information via nmblookup: host does not reply")
    return Result(nmblookup_result, "")

def get_workgroup_from_nmblookup(nmblookup_result):
    '''
    Extract workgroup from given nmblookoup result.
    '''

    match = re.search(r"^\s+(\S+)\s+<00>\s+-\s+<GROUP>\s+", nmblookup_result, re.MULTILINE)
    if match:
        if valid_workgroup(match.group(1)):
            workgroup = match.group(1)
        else:
            return Result(None, f"Workgroup {workgroup} contains some illegal characters")
    else:
        return Result(None, "Can't find workgroup/domain")
    return Result(workgroup, f"Got domain/workgroup name: {workgroup}")

def nmblookup_to_human(nmblookup_result):
    '''
    Map nmblookup output to human readable strings.
    '''

    output = []
    nmblookup_result = nmblookup_result.splitlines()
    for line in nmblookup_result:
        if "Looking up status of" in line or line == "":
            continue

        line = line.replace("\t","")
        match = re.match(r"^(\S+)\s+<(..)>\s+-\s+?(<GROUP>)?\s+?[A-Z]", line)
        if match:
            line_val = match.group(1)
            line_code = match.group(2).upper()
            line_group = False if match.group(3) else True
            for entry in global_nbt_info:
                pattern, code, group, desc = entry
                if pattern:
                    if pattern in line_val and line_code == code and line_group == group:
                        output.append(line + " " + desc)
                        break
                else:
                    if line_code == code and line_group == group:
                        output.append(line + " " + desc)
                        break
        else:
            output.append(line)
    return Result(output, f"Full NetBIOS names information:\n{yaml.dump(output).rstrip()}")

def check_session(target, creds):
    '''
    Tests access to the IPC$ share.

    General explanation:
    The Common Internet File System(CIFS/Server Message Block (SMB) protocol specifies
    mechanisms for interprocess communication over the network. This is called a named pipe.
    In order to be able to "talk" to these named pipes, a special share named "IPC$" is provided.
    SMB clients can access named pipes by using this share. Older Windows versions supported
    anonymous access to this share (empty username and password), which is called a "null sessions".
    This is a security vulnerability since it allows to gain valuable information about the host
    system.

    How the test works:
    In order to test for a null session, the smbclient command is used, by tring to connect to the
    IPC$ share. If that works, smbclient's 'help' command will be run. If the login was successfull,
    the help command will return a list of possible commands. One of these commands is called
    'case_senstive'. We search for this command as an indicator that the IPC session was setup correctly.
    '''

    command = ['smbclient', '-W', target.workgroup, f'//{target.host}/ipc$', '-U', f'{creds.user}%{creds.pw}', '-c', 'help']
    session_output = run(command, "Attempting to make session")

    add_string = ""
    if not creds.user and not creds.pw:
        add_string = " (null session)"

    if "case_sensitive" in session_output:
        return Result(True, f"Server allows session using username '{creds.user}', password '{creds.pw}'{add_string}.")
    return Result(False, f"Server doesn't allow session using username '{creds.user}', password '{creds.pw}'{add_string}.")

    #FIXME: The code snippet below is a 1:1 translation from the original perl code.
    #       I tested the code against various machines. The smbclient command output
    #       will never contain a "Domain=.*" string. I still left it in here, in case
    #       I have something overlooked.
    #if not workgroup:
    #    match = re.search("Domain=\[([^]]*)\]",session_output)
    #    if match and valid_workgroup(match.group[1]):
    #        workgroup = match.group[1]
    #        print(f"[+] Got domain/workgroup name: {workgroup}")

def get_namingcontexts(target):

    # Set network timeout to 3 secods
    ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 3.0)
    # Disable certificate verification
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    if target.tls:
        proto = "ldaps"
    else:
        proto = "ldap"

    try:
        ldap_con = ldap.initialize(f'{proto}://{target.host}')
        contexts = ldap_con.get_naming_contexts()
    except Exception as e:
        return Result(None, "LDAP connect error")

    if not contexts:
        return Result([], "NamingContexts are not readable")

    # Convert all entries from bytes to string
    contexts = [entry.decode('utf-8') for entry in contexts]
    return Result(contexts, "")

def check_parent_dc(namingcontexts_result):
    parent = False
    if "DC=DomainDnsZones" or "ForestDnsZones" in namingcontexts_result:
        parent = True
    if parent:
        return Result(True, "Appears to be root/parent DC")
    return Result(False, "Appears to be child DC")

def get_long_domain(namingcontexts_result):
    long_domain = ""

    for entry in namingcontexts_result:
        match = re.search("(DC=[^,]+,DC=[^,]+)$", entry)
        if match:
            long_domain = match.group(1)
            long_domain = long_domain.replace("DC=", "")
            long_domain = long_domain.replace(",", ".")
            break
    if long_domain:
        return Result(long_domain, f"Long domain name is: {long_domain}")
    return Result(None, "Can't find long domain")

def run_lsaquery(target, creds):
    '''
    Uses the rpcclient command to connect to the named pipe LSARPC (Local Security Authority Remote Procedure Call),
    which allows to do remote management of domain security policies. In this specific case, we use rpcclient's lsaquery
    command. This command will do an LSA_QueryInfoPolicy request to get the domain name and the domain service identifier
    (SID).
    '''

    command = ['rpcclient', '-W', target.workgroup, '-U', f'{creds.user}%{creds.pw}', target.host, '-c', 'lsaquery']
    lsaquery_result = run(command, "Attempting to get domain SID")

    if "NT_STATUS_LOGON_FAILURE" in lsaquery_result:
        return Result(None, "Can't get domain information via lsaquery: NT_STATUS_LOGON_FAILURE")

    if lsaquery_result:
        return Result(lsaquery_result, "")
    return Result(None, "Can't get information via lsaquery")

def check_is_part_of_workgroup_or_domain(lsaquery_result):
    '''
    Takes the result of rpclient's lsaquery command and tries to determine from the result whether the
    is part of a domain or workgroup.
    '''

    if "Domain Sid: S-0-0" in lsaquery_result:
        return Result("workgroup", "[+] Host is part of a workgroup (not a domain)")
    if re.search("Domain Sid: S-\d+-\d+-\d+-\d+-\d+-\d+", lsaquery_result):
        return Result("domain", "Host is part of a domain (not a workgroup)")
    return Result(False, "Can't determine if host is part of domain or part of a workgroup")

def get_workgroup_from_lsaquery(lsaquery_result):
    '''
    Takes the result of rpclient's lsaquery command and tries to extract the workgroup.
    '''

    workgroup = ""
    if "Domain Name" in lsaquery_result:
        match = re.search("Domain Name: (.*)", lsaquery_result)
        if match:
            #FIXME: Validate domain? --> See valid_workgroup()
            workgroup=match.group(1)

    if workgroup:
        return Result(workgroup, f"Domain: {workgroup}")
    return Result(None, "Can't get workgroup from lsaquery")

def get_domain_sid_from_lsaquery(lsaquery_result):
    '''
    Takes the result of rpclient's lsaquery command and tries to extract the domain SID.
    '''

    domain_sid = ""
    match = re.search(r"Domain Sid: (S-\d+-\d+-\d+-\d+-\d+-\d+)", lsaquery_result)
    if match:
        domain_sid = match.group(1)
    if domain_sid:
        return Result(domain_sid, f"SID: {domain_sid}")
    return Result(None, "Can't get domain SID from lsaquery")

def run_srvinfo(target, creds):
    '''
    Uses rpcclient's srvinfo command to connect to the named pipe SRVSVC in order to call
    NetSrvGetInfo() on the target. This will return OS information (OS version, platform id,
    server type).
    '''

    #FIXME: The code snippet below is a 1:1 translation from the original perl code.
    #       I tested the code against various machines. The smbclient command output
    #       will never contain a "Domain=.*" string. I still left it in here, in case
    #       I have something overlooked.
    #command = ['smbclient', '-W', workgroup, f'//{host}/ipc$', '-U', f'{user}%{pw}', '-c', 'q']
    #output = run(command,"Attempting to get OS information")
    #match = re.search('(Domain=[^\n]+)',output)
    #if match:
    #    print(f"[+] Got OS info for {host} from smbclient: {match.group(1)}")

    command = ["rpcclient", "-W", target.workgroup, '-U', f'{creds.user}%{creds.pw}', '-c', 'srvinfo', target.host]
    srvinfo_result = run(command, "Attempting to get OS info with command")

    if "NT_STATUS_ACCESS_DENIED" in srvinfo_result:
        return Result(None, "Can't get OS info with srvinfo: NT_STATUS_ACCESS_DENIED")
    if "NT_STATUS_LOGON_FAILURE" in srvinfo_result:
        return Result(None, "Can't get OS info with srvinfo: NT_STATUS_LOGON_FAILURE")
    return Result(srvinfo_result, "")

# FIXME: Evaluate server_type_string
def get_os_info(srvinfo_result):
    '''
    Takes the result of rpcclient's srvinfo command and tries to extract information like
    platform_id, os version and server type.
    '''

    search_pattern_list = ["platform_id", "os version", "server type"]

    os_info = {}
    first = True
    for line in srvinfo_result.splitlines():
        if first:
            match = re.search("\s+[^\s]+\s+(.*)", line)
            if match:
                os_info['server_type_string'] = match.group(1)
            first = False
        for search_pattern in search_pattern_list:
            match = re.search(fr"\s+{search_pattern}\s+:\s+(.*)", line)
            if match:
                # os version => os_version, server type => server_type
                search_pattern = search_pattern.replace(" ", "_")
                os_info[search_pattern] = match.group(1)
    if not os_info:
        return Result(None, "Couldn't get OS information")

    retmsg = "The following OS information were found:\n"
    for key, value in os_info.items():
        retmsg += (f"{key:18} = {value}\n")
    retmsg = retmsg.rstrip()
    return Result(os_info, retmsg)

def run_querydispinfo(target, creds):
    '''
    querydispinfo uses the Security Account Manager Remote Protocol (SAMR) named pipe to run the QueryDisplayInfo() request.
    This request will return users with their corresponding Relative ID (RID) as well as multiple account information like a
    description of the account.
    '''

    command = ['rpcclient', '-W', target.workgroup, '-c', 'querydispinfo', '-U', f'{creds.user}%{creds.pw}', target.host]
    querydispinfo_result = run(command, "Attempting to get userlist")

    if "NT_STATUS_ACCESS_DENIED" in querydispinfo_result:
        return Result(None, "Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED")
    if "NT_STATUS_INVALID_PARAMETER" in querydispinfo_result:
        return Result(None, "Couldn't find users using querydispinfo: NT_STATUS_INVALID_PARAMETER")
    return Result(querydispinfo_result, "")

def run_enumdomusers(target, creds):
    '''
    enomdomusers command will again use the SAMR named pipe to run the EnumDomainUsers() request. This will again
    return a list of users with their corresponding RID (see run_querydispinfo()). This is possible since by default
    the registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous = 0. If this is set to
    1 enumeration is no longer possible.
    '''

    command = ["rpcclient", "-W", target.workgroup, "-c", "enumdomusers", "-U", f"{creds.user}%{creds.pw}", target.host]
    enumdomusers_result = run(command, "Attempting to get userlist")

    if "NT_STATUS_ACCESS_DENIED" in enumdomusers_result:
        return Result(None, "Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED")
    if "NT_STATUS_INVALID_PARAMETER" in enumdomusers_result:
        return Result(None, "Couldn't find users using enumdomusers: NT_STATUS_INVALID_PARAMETER")
    return Result(enumdomusers_result, "")

def enum_users_from_querydispinfo(target, creds):
    users = {}
    querydispinfo = run_querydispinfo(target, creds)

    if querydispinfo.retval is None:
        return querydispinfo

    # Example output of rpcclient's querydispinfo:
    # index: 0x2 RID: 0x3e9 acb: 0x00000010 Account: tester	Name: 	Desc:
    for line in querydispinfo.retval.splitlines():
        match = re.search("index:\s+.*\s+RID:\s+(0x[A-F-a-f0-9]+)\s+acb:\s+(.*)\s+Account:\s+(.*)\s+Name:\s+(.*)\s+Desc:\s+(.*)", line)
        if match:
            rid = match.group(1)
            rid = str(int(rid, 16))
            acb = match.group(2)
            username = match.group(3)
            name = match.group(4)
            description = match.group(5)
            users[rid] = {"username":username, "name":name, "acb":acb, "description":description}
        else:
            return Result(None, "Couldn't extract users from querydispinfo output")
    if users:
        return Result(users, f"Found {len(users.keys())} via 'querydispinfo'")
    return Result(users, "Got an empty response, there are no users (this is not an error, there seem to be really none)")

def enum_users_from_enumdomusers(target, creds):
    users = {}
    enumdomusers = run_enumdomusers(target, creds)

    if enumdomusers.retval is None:
        return enumdomusers

    # Example output of rpcclient's enumdomusers:
    # user:[tester] rid:[0x3e9]
    for line in enumdomusers.retval.splitlines():
        match = re.search("user:\[(.*)\]\srid:\[(0x[A-F-a-f0-9]+)\]", line)
        if match:
            username = match.group(1)
            rid = match.group(2)
            rid = str(int(rid, 16))
            users[rid] = {"username":username}
        else:
            return Result(None, "Couldn't extract users from eumdomusers output")
    if users:
        return Result(users, f"Found {len(users.keys())} via 'enumdomusers'")
    return Result(users, "Got an empty response, there are no users (this is not an error, there seem to be really none)")

def get_user_details_from_rid(rid, target, creds):
    '''
    Takes an RID and makes use of the SAMR named pipe to call QueryUserInfo() on the given RID.
    The output contains lots of information about the corresponding user account.
    '''

    if not valid_rid(rid):
        return Result(None, f"Invalid rid passed: {rid}")

    details = OrderedDict()
    command = ["rpcclient", "-W", target.workgroup, "-U", f"{creds.user}%{creds.pw}", "-c", f"queryuser {rid}", target.host]
    output = run(command, "Attempting to get detailed user info")

    match = re.search("([^\n]*User Name.*logon_hrs[^\n]*)", output, re.DOTALL)
    if match:
        user_info = match.group(1)
        user_info = user_info.replace("\t", "")

        for line in user_info.splitlines():
            if ':' in line:
                (key, value) = line.split(":", 1)
                key = key.rstrip()
                details[key] = value
            else:
                details[line] = ""

        if "acb_info" in details and valid_hex(details["acb_info"]):
            for key in global_acb_dict.keys():
                if int(details["acb_info"], 16) & key:
                    details[global_acb_dict[key]] = True
                else:
                    details[global_acb_dict[key]] = False

        return Result(details, f"Found user details for user with RID {rid}")
    return Result(details, f"Couldn't find user details for user with RID {rid}")

def run_enum_groups(grouptype, target, creds):
    '''
    Tries to fetch groups via rpcclient's enumalsgroups (so called alias groups) and enumdomgroups.
    Grouptype "builtin", "local" and "domain" are supported.
    '''

    grouptype_dict = {
        "builtin":"enumalsgroups builtin",
        "local":"enumalsgroups domain",
        "domain": "enumdomgroups"
    }

    if grouptype not in ["builtin", "domain", "local"]:
        return Result(None, f"Unsupported grouptype, supported types are: { ','.join(groutype_dict.keys()) }")

    command = ["rpcclient", "-W", target.workgroup, "-U", f"{creds.user}%{creds.pw}", target.host, "-c", f"{grouptype_dict[grouptype]}"]
    groups_string = run(command, f"Attempting to get {grouptype} groups")

    if "error: NT_STATUS_ACCESS_DENIED" in groups_string:
        return Result(None, f"Can't get groups via {grouptype_dict[grouptype]}: NT_STATUS_ACCESS_DENIED")
    return Result(groups_string, "")

def enum_groups(grouptype, target, creds, detailed):
    grouptype_dict = {
        "builtin":"enumalsgroups builtin",
        "local":"enumalsgroups domain",
        "domain": "enumdomgroups"
    }

    if grouptype not in ["builtin", "domain", "local"]:
        return Result(None, f"Unsupported grouptype, supported types are: { ','.join(grouptype_dict.keys()) }")

    groups = {}
    enum = run_enum_groups(grouptype, target, creds)
    if enum.retval is None:
        return enum

    match = re.search("(group:.*)", enum.retval, re.DOTALL)
    if not match:
        return Result(None, f"Can't parse result of {grouptype_dict[grouptype]} command")

    # Example output of rpcclient's group commands:
    # group:[RAS and IAS Servers] rid:[0x229]
    for line in enum.retval.splitlines():
        match = re.search("group:\[(.*)\]\srid:\[(0x[A-F-a-f0-9]+)\]", line)
        if match:
            groupname = match.group(1)
            rid = match.group(2)
            rid = str(int(rid, 16))
            groups[rid] = {"groupname":groupname, "type":grouptype}
        else:
            return Result(None, f"Couldn't extract groups from {grouptype_dict[grouptype]} output")
    if groups:
        return Result(groups, f"Found {len(groups.keys())} groups via '{grouptype_dict[grouptype]}'")
    return Result(groups, "Got an empty response, there are no groups (this is not an error, there seem to be really none)")

def get_group_members_from_name(groupname, target, creds):
    command = ["net", "rpc", "group" , "members", groupname, "-W", target.workgroup, "-I", target.host, "-U", f"{creds.user}%{creds.pw}"]
    members_string = run(command, f"Attempting to get group memberships for group {groupname}")
    members = []
    for member in members_string.splitlines():
        if "Couldn't lookup SIDs" in member:
            return Result(None, f"Members lookup failed for group {groupname} due to insufficient user permissions, try a different user")
        members.append(member)

    if members:
        return Result(','.join(members), f"Found {len(members)} member(s) for group '{groupname}'")
    return Result('', f"Couldn't find members for group '{groupname}'")

def get_group_details_from_rid(rid, target, creds):
    '''
    Takes an RID and makes use of the SAMR named pipe to open the group with OpenGroup() on the given RID.
    '''

    if not valid_rid(rid):
        return Result(None, f"Invalid rid passed: {rid}")

    details = OrderedDict()
    command = ["rpcclient", "-W", target.workgroup, "-U", f'{creds.user}%{creds.pw}', "-c", f"querygroup {rid}", target.host]
    output = run(command, "Attempting to get detailed group info")

    #FIXME: Only works for domain groups, otherwise NT_STATUS_NO_SUCH_GROUP is returned
    match = re.search("([^\n]*Group Name.*Num Members[^\n]*)", output, re.DOTALL)
    if match:
        group_info = match.group(1)
        group_info = group_info.replace("\t", "")

        for line in group_info.splitlines():
            if ':' in line:
                (key, value) = line.split(":", 1)
                details[key] = value
            else:
                details[line] = ""

        return Result(details, f"Found group details for group with RID {rid}")
    return Result(details, f"Couldn't find group details for group with RID {rid}")

def check_share_access(share, target, creds):
    command = ["smbclient", "-W", target.workgroup, f"//{target.host}/{share}", "-U", f"{creds.user}%{creds.pw}", "-c", "dir"]
    output = run(command, f"Attempting to map share //{target.host}/{share}")

    if "NT_STATUS_BAD_NETWORK_NAME" in output:
        return Result(None, "[E] Share doesn't exist")

    if "NT_STATUS_ACCESS_DENIED listing" in output:
        return Result({"mapping":"ok", "listing":"denied"}, "Mapping: OK, Listing: DENIED")

    if "tree connect failed: NT_STATUS_ACCESS_DENIED" in output:
        return Result({"mapping":"denied","listing":"n/a"}, "Mapping: DENIED, Listing: N/A")

    if "NT_STATUS_INVALID_INFO_CLASS" in output:
        return Result({"mapping":"ok","listing":"not supported"}, f"Mapping: OK, Listing: NOT SUPPORTED")

    if re.search("\n\s+\.\.\s+D.*\d{4}\n", output):
        return Result({"mapping":"ok","listing":"ok"}, "Mapping: OK, Listing: OK")

    # FIXME: Here we might get an NT_STATUS_OBJECT_NAME_NOT_FOUND
    return Result(None, "Can't understand smbclient response")

def enum_shares(target, creds):
    '''
    Tries to enumerate shares with the given username and password. It does this running the smbclient command.
    smbclient will open a connection to the Server Service Remote Protocol named pipe (srvsvc). Once connected
    it calls the NetShareEnumAll() to get a list of shares.
    For the list of resulting shares, smbclient is used again with the "dir" command. In the background this will
    send an SMB I/O Control (IOCTL) request in order to list the contents of the share.
    '''

    # FIXME: Test: net rpc share -W 'workgroup' -I host -U'user%pw'
    command = ["smbclient", "-W", target.workgroup, "-L", f"//{target.host}", "-U", f"{creds.user}%{creds.pw}"]
    shares_result = run(command, "Attempting to get share list using authentication")

    if "NT_STATUS_ACCESS_DENIED" in shares_result:
        return Result(None, "Can't list shares: NT_STATUS_ACCESS_DENIED")

    shares = {}
    match_list = re.findall("\n\s*([ \S]+?)\s+(?:Disk|IPC|Printer)", shares_result, re.IGNORECASE)
    if match_list:
        for share in match_list:
            shares[share] = {}

    if shares:
        return Result(shares, f"Found {len(shares.keys())} shares: {','.join(shares.keys())}")
    return Result(None, f"No shares found for user '{creds.user}' with password '{creds.pw}', try a different user")

def enum_sids(target, creds):
    sids = []
    sid_patterns_list = ["(S-1-5-21-[\d-]+)-\d+", "(S-1-5-[\d-]+)-\d+", "(S-1-22-[\d-]+)-\d+"]

    if creds.user:
        known_username += f",{creds.user}"

    # Try to get a valid SID from well-known user names
    for known_username in global_known_usernames.split(','):
        command = ["rpcclient", "-W", target.workgroup, "-U", f"{creds.user}%{creds.pw}", target.host, "-c", f"lookupnames {known_username}"]
        sid_string = run(command, f"Attempting to get SID for user {known_username}")

        if "NT_STATUS_ACCESS_DENIED" or "NT_STATUS_NONE_MAPPED" in sid_string:
            continue

        for pattern in sid_patterns_list:
            match = re.search(pattern, sid_string)
            if match:
                result = match.group(1)
                if result not in sids:
                    sids.append(result)

    # Try to get SID list via lsaenumsid
    command = ["rpcclient", "-W", target.workgroup, "-U", f"{creds.user}%{creds.pw}", "-c", "lsaenumsid", target.host]
    sids_string = run(command, f"Attempting to get SIDs via lsaenumsid")

    if "NT_STATUS_ACCESS_DENIED" not in sids_string:
        for pattern in sid_patterns_list:
            match_list = re.findall(pattern, sids_string)
            for result in match_list:
                if result not in sids:
                    sids.append(result)

    if sids:
        return Result(sids, f"Found {len(sids)} SIDs")
    return Result(None, "Couldn't get any SIDs")

def prepare_rid_ranges(rid_ranges):
    rid_ranges_list = []

    for rid_range in rid_ranges.split(','):
        if rid_range.isdigit():
            start_rid = rid_range
            end_rid = rid_range
        else:
            [start_rid, end_rid] = rid_range.split("-")

        start_rid = int(start_rid)
        end_rid = int(end_rid)

        # Reverse if neccessary
        if start_rid > end_rid:
            start_rid, end_rid = end_rid, start_rid

        rid_ranges_list.append((start_rid, end_rid))

    return rid_ranges_list

def rid_cycle(sid, rid_ranges, target, creds):

    for rid_range in rid_ranges:
        (start_rid, end_rid) = rid_range

        for rid in range(start_rid, end_rid):
            command = ["rpcclient", "-W", target.workgroup, "-U", f"{creds.user}%{creds.pw}", target.host, "-c", f"lookupsids {sid}-{rid}"]
            output = run(command, "RID Cycling")

            # Example: S-1-5-80-3139157870-2983391045-3678747466-658725712-1004 *unknown*\*unknown* (8)
            match = re.search("(S-\d+-\d+-\d+-[\d-]+\s+(.*)\s+[^\)]+\))", output)
            if match:
                sid_and_user = match.group(1)
                entry = match.group(2)

	        # Samba servers sometimes claim to have user accounts
	        # with the same name as the UID/RID. We don't report these.
                if re.search("-(\d+) .*\\\1 \(", sid_and_user):
                    continue
                    
                # "(1)" = User, "(2)" = Domain Group,"(3)" = Domain SID,"(4)" = Local Group
                # "(5)" = Well-known group, "(6)" = Deleted account, "(7)" = Invalid account
                # "(8)" = Unknown, "(9)" = Machine/Computer account
                result = None
                if "(1)" in sid_and_user:
                    yield Result({"users":{ str(rid):{ "username":entry}}}, f"Found user {entry}")
                elif "(2)" in sid_and_user:
                    yield Result({"groups":{str(rid):{"groupname":entry, "type":"domain"}}}, f"Found domain group {entry}")
                elif "(3)" in sid_and_user:
                    yield Result({"domain_sid":f"{sid}-{rid}"}, f"Found domain SID {sid}-{rid}")
                elif "(4)" in sid_and_user:
                    yield Result({"groups":{str(rid):{"groupname":entry, "type":"builtin"}}}, f"Found builtin group {entry}")
                elif "(9)" in sid_and_user:
                    yield Result({"machines":{str(rid):{"machine":entry}}}, f"Found machine {entry}")

#FIXME: Parse output - need to setup test env.
def enum_printers(target, creds):
    command = ["rpcclient", "-W", target.workgroup, "-U", f"{creds.user}%{creds.pw}", "-c", "enumprinters", target.host]
    printer_info = run(command, "Attempting to get printer info")

    if printer_info:
        if "NT_STATUS_OBJECT_NAME_NOT_FOUND" in printer_info:
            return Result("", f"No printer available")
        if "NT_STATUS_ACCESS_DENIED" in printer_info:
            return Result(None, f"Can't get printer info: NT_STATUS_ACCESS_DENIED")
        return Result(printer_info, f"Got printer info:\n{printer_info}")
    return Result(None, f"No printer info found")

# This function is heavily based on the polenum.py source code: https://github.com/Wh1t3Fox/polenum
# All credits to Wh1t3Fox!
def samr_init(target, creds):
    rpctransport = transport.SMBTransport(target.host, target.port, r'\samr', creds.user, creds.pw)
    try:
        dce = DCERPC_v5(rpctransport)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
    except Exception as e:
        return Result((None, None), "DCE/SAMR connect failed")

    resp = samr.hSamrConnect2(dce)
    if resp['ErrorCode'] != 0:
        return Result((None, None), "SamrConnect failed")

    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle=resp['ServerHandle'], enumerationContext=0, preferedMaximumLength=500)
    if resp2['ErrorCode'] != 0:
        return Result((None, None), "SamrEnumerateDomainsinSamServer failed")

    resp3 = samr.hSamrLookupDomainInSamServer(dce, serverHandle=resp['ServerHandle'], name=resp2['Buffer']['Buffer'][0]['Name'])
    if resp3['ErrorCode'] != 0:
        return Result((None, None), "SamrLookupDomainInSamServer failed")

    resp4 = samr.hSamrOpenDomain(dce, serverHandle=resp['ServerHandle'], desiredAccess=samr.MAXIMUM_ALLOWED, domainId=resp3['DomainId'])
    if resp4['ErrorCode'] != 0:
        return Result((None, None), "SamrOpenDomain failed")

    #domains = resp2['Buffer']['Buffer']
    domain_handle = resp4['DomainHandle']

    return Result((dce, domain_handle), "")

# This function is heavily based on the polenum.py source code: https://github.com/Wh1t3Fox/polenum
# All credits to Wh1t3Fox!
def enum_policy(target, creds):
    policy = {}

    result = samr_init(target, creds)
    if result.retval[0] is None or result.retval[1] is None:
        return Result(None, result.retmsg)

    dce, domain_handle = result.retval

    # Password policy
    domain_passwd = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
    result = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=domain_passwd)

    min_pw_len = result['Buffer']['Password']['MinPasswordLength'] or "None"
    policy["min_pw_length"] = min_pw_len

    pw_history_len = result['Buffer']['Password']['PasswordHistoryLength'] or "None"
    policy["pw_history_length"] = pw_history_len

    max_pw_age = policy_to_human(int(result['Buffer']['Password']['MaxPasswordAge']['LowPart']), int(result['Buffer']['Password']['MaxPasswordAge']['HighPart']))
    policy["max_pw_age"] = max_pw_age

    min_pw_age = policy_to_human(int(result['Buffer']['Password']['MinPasswordAge']['LowPart']), int(result['Buffer']['Password']['MinPasswordAge']['HighPart']))
    policy["min_pw_age"] = min_pw_age

    policy["pw_properties"] = []
    pw_prop = result['Buffer']['Password']['PasswordProperties']
    for bitmask in global_domain_fields.keys():
        if pw_prop & bitmask == bitmask:
            policy["pw_properties"].append(global_domain_field[bitmask])

    # Domain lockout
    domain_lockout = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
    result = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=domain_lockout)

    lockout_observation_window = policy_to_human(0, result['Buffer']['Lockout']['LockoutObservationWindow'], lockout=True)
    policy["lockout_observation_window"] = lockout_observation_window

    lockout_duration = policy_to_human(0, result['Buffer']['Lockout']['LockoutDuration'], lockout=True)
    policy["lockout_duration"] = lockout_duration

    lockout_threshold = result['Buffer']['Lockout']['LockoutThreshold'] or "None"
    policy["lockout_threshold"] = lockout_threshold

    # Domain logoff
    domain_logoff = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
    result = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=domain_logoff)
    force_logoff_time = policy_to_human(result['Buffer']['Logoff']['ForceLogoff']['LowPart'], result['Buffer']['Logoff']['ForceLogoff']['HighPart'])
    policy["force_logoff_time"] = force_logoff_time

    return Result(policy, f"Found policy:\n{yaml.dump(policy).rstrip()}")

# This function was copied (slightly modified) from the polenum.py source code: https://github.com/Wh1t3Fox/polenum
# All credits to Wh1t3Fox!
def policy_to_human(low, high, lockout=False):
    time = ""
    tmp = 0

    if low == 0 and hex(high) == "-0x80000000":
        return "not Set"
    if low == 0 and high == 0:
        return "none"

    if not lockout:
        if low != 0:
            high = abs(high+1)
        else:
            high = abs(high)
            low = abs(low)

        tmp = low + (high)*16**8  # convert to 64bit int
        tmp *= (1e-7)  # convert to seconds
    else:
        tmp = abs(high) * (1e-7)

    try:
        minutes = int(strftime("%M", gmtime(tmp)))
        hours = int(strftime("%H", gmtime(tmp)))
        days = int(strftime("%j", gmtime(tmp)))-1
    except ValueError as e:
        return "Invalid time"

    if days > 1:
        time += f"{days} days "
    elif days == 1:
        time += f"{days} day "
    if hours > 1:
        time += f"{hours} hours "
    elif hours == 1:
        time += f"{hours} hour "
    if minutes > 1:
        time += f"{minutes} minutes"
    elif minutes == 1:
        time += f"{minutes} minute"
    return time

def run(command, description=""):
    '''
    Run command and do some basic output filtering.
    '''

    if global_verbose and description:
        # Works only in Python 3.8, which currently conflicts with some impacket stuff
        #print(f"[V] {description}, running command: {shlex.join(command)}")
        print_verbose(f"{description}, running command: {' '.join(shlex.quote(x) for x in command)}")

    try:
        output = subprocess.check_output(command, shell=False, stderr=subprocess.STDOUT)
    except Exception as e:
        output = e.output

    output = output.decode()
    # Workaround for Samba bug (see https://bugzilla.samba.org/show_bug.cgi?id=13925)
    output = output.replace("Unable to initialize messaging context\n", "")
    output = output.rstrip('\n')
    return output

def run_module_netbios(target, creds):
    module_name = "netbios"
    print_heading(f"Getting NetBIOS names for {target.host}")
    output = {}

    nmblookup = run_nmblookup(target.host)
    if nmblookup.retval:
        result = get_workgroup_from_nmblookup(nmblookup.retval)
        if result.retval:
            print_success(result.retmsg)
            # If the given workgroup was empty, we set it
            if not target.workgroup:
                output["workgroup"] = result.retval
        else:
            output = process_error(result.retmsg, module_name, output)

        result = nmblookup_to_human(nmblookup.retval)
        print_success(result.retmsg)
        output["nmblookup"] = result.retval
    else:
        output = process_error(nmblookup.retmsg, module_name, output)

    return output

def run_module_session_check(target, creds):
    module_name = "session_check"
    print_heading(f"Session Check on {target.host}")
    output = {}

    # Check null session
    output["null_session_possible"] = False
    null_session = check_session(target, Credentials('', ''))
    if null_session.retval:
        output["null_session_possible"] = True
        print_success(null_session.retmsg)
    else:
        output = process_error(null_session.retmsg, module_name, output)

    # Check user session
    if creds.user:
        output["user_session_possible"] = False
        user_session = check_session(target, creds)
        if user_session.retval:
            output["user_session_possible"] = True
            print_success(user_session.retmsg)
        else:
            output = process_error(user_session.retmsg, module_name, output)

    output["sessions_possible"] = False
    if ("null_session_possible" in output and output["null_session_possible"]) or \
        ("user_session_possible" in output and output["user_session_possible"]):
        output["sessions_possible"] = True

    return output

def run_module_ldapsearch(target, creds):
    module_name = "ldapsearch"
    print_heading(f"Getting information via LDAP for {target.host}")
    output = {}

    add_string = ""
    for with_tls in [False, True]:
        if with_tls:
            add_string = "secure "
        print_info(f'Trying {add_string}LDAP')
        target.tls = with_tls
        namingcontexts = get_namingcontexts(target)
        if namingcontexts.retval is not None:
            break
        output = process_error(namingcontexts.retmsg, module_name, output)

    if namingcontexts.retval:
        # Parent/root or child DC?
        result = check_parent_dc(namingcontexts.retval)
        if result.retval:
            output["is_parent_dc"] = True
            output["is_child_dc"] = False
        else:
            output["is_parent_dc"] = True
            output["is_child_dc"] = False
        print_success(result.retmsg)

        # Try to get long domain from ldapsearch result
        result = get_long_domain(namingcontexts.retval)
        if result.retval:
            print_success(result.retmsg)
            output["long_domain"] = result.retval
        else:
            output = process_error(result.retmsg, module_name, output)

    return output

def run_module_lsaquery(target, creds):
    module_name = "lsaquery"
    print_heading(f"Getting domain information for {target.host}")
    output = {}

    lsaquery = run_lsaquery(target, creds)
    if lsaquery.retval is not None:
        # Try to get domain/workgroup from lsaquery
        result = get_workgroup_from_lsaquery(lsaquery.retval)
        if result.retval:
            print_success(result.retmsg)
            if not target.workgroup:
                output["workgroup"] = result.retval
        else:
            output = process_error(result.retmsg, module_name, output)

        # Try to get domain SID
        result = get_domain_sid_from_lsaquery(lsaquery.retval)
        if result.retval:
            print_success(result.retmsg)
            output["domain_sid"] = result.retval
        else:
            output = process_error(result.retmsg, module_name, output)

        # Is the host part of a domain or a workgroup?
        result = check_is_part_of_workgroup_or_domain(lsaquery.retval)
        if result.retval:
            print_success(result.retmsg)
            output["member_of"] = result.retval
        else:
            output = process_error(result.retmsg, module_name, output)
    else:
        output = process_error(lsaquery.retmsg, module_name, output)

    return output

def run_module_srvinfo(target, creds):
    module_name = "srvinfo"
    print_heading(f"OS information on {target.host}")
    output = {}

    srvinfo = run_srvinfo(target, creds)
    if srvinfo.retval:
        osinfo = get_os_info(srvinfo.retval)
        if osinfo.retval:
            print_success(osinfo.retmsg)
            output["os info"] = osinfo.retval
        else:
            output = process_error(osinfo.retmsg, module_name, output)
    else:
        output = process_error(srvinfo.retmsg, module_name, output)

    return output

def run_module_enum_users(target, creds, detailed):
    module_name = "enum_users"
    print_heading(f"Users on {target.host}")
    output = {}

    print_info("Enumerating users")
    # Get user via querydispinfo
    users_qdi = enum_users_from_querydispinfo(target, creds)
    if users_qdi.retval is None:
        output = process_error(users_qdi.retmsg, module_name, output)
        users_qdi_output = {}
    else:
        print_success(users_qdi.retmsg)
        users_qdi_output = users_qdi.retval

    # Get user via enumdomusers
    users_edu = enum_users_from_enumdomusers(target, creds)
    if users_edu.retval is None:
        output = process_error(users_edu.retmsg, module_name, output)
        users_edu_output = {}
    else:
        print_success(users_edu.retmsg)
        users_edu_output = users_edu.retval

    # Merge both users dicts
    users = {**users_edu_output, **users_qdi_output}

    if users:
        if detailed:
            print_info("Enumerating users details")
            for rid in users.keys():
                user_details = get_user_details_from_rid(rid, target, creds)
                if user_details.retval:
                    print_success(user_details.retmsg)
                    users[rid]["details"] = user_details.retval
                else:
                    output = process_error(users_details.retmsg, module_name, output)
                    users[rid]["details"] = ""

        print_success(f"After merging user results we have {len(users.keys())} users total:\n{yaml.dump(users).rstrip()}")

    output["users"] = users
    return output

def run_module_enum_groups(target, creds, with_members, detailed):
    module_name = "enum_groups"
    print_heading(f"Groups on {target.host}")
    output = {}
    groups = {}

    print_info("Enumerating groups")
    for grouptype in ["local", "builtin", "domain"]:
        enum = enum_groups(grouptype, target, creds, detailed)
        if enum.retval is None:
            output = process_error(enum.retmsg, module_name, output)
        else:
            print_success(enum.retmsg)
            groups.update(enum.retval)

    #FIXME: Adjust users enum stuff above so that it looks similar to this one?
    #FIXME: One function now uses the groupname while the other uses the RID, make at least the output equal
    if groups:
        if with_members:
            print_info("Enumerating group members")
            for rid in groups.keys():
                # Get group members
                groupname = groups[rid]['groupname']
                group_members = get_group_members_from_name(groupname, target, creds)
                if group_members.retval:
                    print_success(group_members.retmsg)
                    groups[rid]["members"] = group_members.retval
                else:
                    groups[rid]["members"] = ""
                    output = process_error(group_members.retmsg, module_name, output)

                #FIXME: Return value None for everything which was not "filled" out in the current run?
                #groups[rid]["details"] = None
        if detailed:
            print_info("Enumerating group details")
            for rid in groups.keys():
                group_details = get_group_details_from_rid(rid, target, creds)
                if group_details.retval:
                    print_success(group_details.retmsg)
                    groups[rid]["details"] = group_details.retval
                else:
                    output = process_error(group_details.retmsg, module_name, output)
                    groups[rid]["details"] = ""
        print_success(f"After merging groups results we have {len(groups.keys())} groups total:\n{yaml.dump(groups).rstrip()}")
    output["groups"] = groups
    return output

def run_module_rid_cycling(cycle_params, target, creds, detailed):
    module_name = "rid_cycling"
    print_heading(f"Users, Groups and Machines on {target.host} via RID cycling")
    output = cycle_params.enumerated_input

    # Try to enumerated SIDs first, if we don't have the domain SID already
    if output["domain_sid"]:
        sids_list = [output["domain_sid"]]
    else:
        print_info(f"Trying to enumerate SIDs")
        sids = enum_sids(target, creds)
        if sids.retval is None:
            output = process_error(sids.retmsg, module_name, output)
            return output
        print_success(sids.retmsg)
        sids_list = sids.retval

    # Keep track of what we found...
    found_count = {"users": 0, "groups": 0, "machines": 0}

    # Run...
    for sid in sids_list:
        print_info(f"Trying SID {sid}")
        rid_cycler = rid_cycle(sid, cycle_params.rid_ranges, target, creds)
        for result in rid_cycler:
            # We need the top level key to find out whether we got users, groups, machines or the domain_sid...
            top_level_key = list(result.retval.keys())[0]

            # We found the domain_sid...
            if top_level_key == 'domain_sid':
                output['domain_sid'] = result.retval['domain_sid']
                continue

            # ...otherwise "users", "groups" or "machines".
            # Get the RID of what we found (user, group or machine RID) as well as the corresponding entry (dict).
            rid = list(result.retval[top_level_key])[0]
            entry = result.retval[top_level_key][rid]

            # If we have the RID already, we continue...
            if rid in output[top_level_key]:
                continue

            print_success(result.retmsg)
            found_count[top_level_key]+=1

            # ...else we add the result at the right position.
            output[top_level_key][rid] = entry

            if detailed:
                if "users" in top_level_key:
                    rid, entry = list(result.retval["users"].keys())[0]
                    details = get_user_details_from_rid(rid, target, creds)
                elif "groups" in top_level_key:
                    rid, entry = list(result.retval["users"].keys())[0]
                    details = get_group_details_from_rid(rid, target, creds)
                output[top_level_key][rid]["details"] = details

    if found_count["users"] == 0 and found_count["groups"] == 0 and found_count["machines"] == 0:
        output = process_error(f"Could not find any (new) users, (new) groups or (new) machines", module_name, output)
    else:
        print_success(f"Found {found_count['users']} user(s), {found_count['groups']} group(s), {found_count['machines']} machine(s)")

    return output

def run_module_enum_shares(target, creds):
    module_name = "enum_shares"
    print_heading(f"Share enumeration on {target.host}")
    output = {}
    shares = {}

    enum = enum_shares(target, creds)
    if enum.retval is None:
        output = process_error(enum.retmsg, module_name, output)
    else:
        # This will print success even if no shares were found (which is not an error.)
        print_success(enum.retmsg)
        shares = enum.retval
        # Check access if there are any shares.
        if enum.retmsg:
            for share in shares.keys():
                print_info(f"Testing share {share}")
                access = check_share_access(share, target, creds)
                if access.retval is None:
                    output = process_error(access.retmsg, module_name, output)
                    continue
                print_success(access.retmsg)
                shares[share] = access.retval

    output["shares"] = shares
    return output

def run_module_bruteforce_shares(shares_file, target, creds):
    module_name = "bruteforce_shares"
    print_heading(f"Share bruteforcing on {target.host}")
    output = {}
    shares = {}

    try:
        with open(shares_file) as f:
            for share in f:
                share = share.rstrip()
                result = check_share_access(share, target, creds)
                if result.retval:
                    print_success(f"Found share: {share}\n\t{result.retmsg}")
                    shares[share] = result.retmsg
    except:
        output = process_error(f"Failed to open {shares_file}", module_name, output)

    output["shares"] = shares
    return output

def run_module_enum_policy(target, creds):
    module_name = "enum_policy"
    print_heading(f"Password Policy Information for {target.host}")
    output = {}

    for port in [139, 445]:
        print_info(f"Trying port {port}/tcp")
        target.port = port
        enum = enum_policy(target, creds)
        if enum.retval is None:
            output = process_error(enum.retmsg, module_name, output)
            output["policy"] = None
        else:
            print_success(enum.retmsg)
            output["policy"] = enum.retval

    return output

def run_module_enum_printers(target, creds):
    module_name = "enum_printers"
    print_heading(f"Getting printer info for {target.host}")
    output = {}

    enum = enum_printers(target, creds)
    if enum.retval is None:
        output = process_error(enum.retmsg, module_name, output)
    else:
        print_success(enum.retmsg)
        output["printers"] = enum.retval
    return output

def valid_rid_ranges(rid_ranges):
    if not rid_ranges:
        return False

    for rid_range in rid_ranges.split(','):
        match = re.search("(\d+)-(\d+)", rid_range)
        if match:
            continue
        if rid_range.isdigit():
            continue
        return False
    return True

def valid_shares_file(shares_file):
    fault_shares = []
    nl = '\n'

    if not os.path.exists(shares_file):
        return Result(False, f"Shares file {shares_file} does not exist")

    if os.stat(shares_file).st_size == 0:
        return Result(False, f"Shares file {shares_file} is empty")

    try:
        with open(shares_file) as f:
            line_num = 1
            for share in f:
                share = share.rstrip()
                if not valid_share(share):
                    fault_shares.append(f"line {line_num}:{share}")
    except:
        return Result(False, f"Can't open shares file {shares_file}")
    if fault_shares:
        return Result(False, f"These shares contain illegal characters:\n{nl.join(fault_shares)}")
    return Result(True, "")

def valid_share(share):
    if re.search("^[a-zA-Z0-9\._\$-]+$", share):
        return True
    return False

def valid_hex(hexnumber):
    if re.search("^0x[0-9a-f]+$", hexnumber.lower()):
        return True
    return False

def valid_rid(rid):
    if isinstance(rid, int) and rid > 0:
        return True
    if rid.isdigit():
        return True
    return False

def valid_workgroup(workgroup):
    if re.match("^[A-Za-z0-9_\.-]+$", workgroup):
        return True
    return False

def valid_host(host):
    if re.match("^([a-zA-Z0-9\._-]+)$", host):
        return True
    return False

def check_args(argv):
    global global_verbose

    parser = argparse.ArgumentParser(argv)
    parser.add_argument("host")
    parser.add_argument("-A", action="store_true", help="Do all simple enumeration (-U -G -S -P -R -O -N -I). This option is enabled if you don't provide any other option.")
    parser.add_argument("-U", action="store_true", help="Get userlist")
    parser.add_argument("-G", action="store_true", help="Get groups")
    parser.add_argument("-Gm", action="store_true", help="Get groups and member list")
    parser.add_argument("-M", action="store_true", help="Get machine list*")
    parser.add_argument("-S", action="store_true", help="Get sharelist")
    parser.add_argument("-P", action="store_true", help="Get password policy information")
    parser.add_argument("-O", action="store_true", help="Get os information")
    parser.add_argument("-L", action="store_true", help="Get some info via LDAP/LDAPS (for DCs only)")
    parser.add_argument("-I", action="store_true", help="Get printer information")
    parser.add_argument("-R", action="store_true", help="Enumerate users via RID cycling")
    parser.add_argument("-N", action="store_true", help="Do an nmblookup (similar to nbstat) and try to retrieve workgroup from nmblookup output")
    parser.add_argument("-w", dest="workgroup", default='', type=str, help="Specify workgroup manually (usually found automatically)")
    parser.add_argument("-u", dest="user", default='', type=str, help="Specify username to use (default "")")
    parser.add_argument("-p", dest="pw", default='', type=str, help="Specify password to use (default "")")
    parser.add_argument("-d", action="store_true", help="Be detailed, applies to -U, -G and -r")
    parser.add_argument("-k", dest="users", default=global_known_usernames, type=str, help=f'User(s) that exists on remote system (default: {global_known_usernames}.\nUsed to get sid with "lookupsid known_username"')
    parser.add_argument("-r", dest="ranges", default=global_rid_ranges, type=str, help=f"RID ranges to enumerate (default: {global_rid_ranges}, implies -r")
    parser.add_argument("-s", dest="shares_file", help="Brute force guessing for share names")
    parser.add_argument("-oJ", dest="out_json_file", help="Writes output to JSON file")
    parser.add_argument("-oY", dest="out_yaml_file", help="Writes output to YAML file")
    parser.add_argument("-v", dest="verbose", action="store_true", help="Verbose, show full commands being run (net, rpcclient, etc.)")
    args = parser.parse_args(sys.argv[1:])

    if args.host and (len(argv) == 1 or (len(argv) == 3 and (args.out_json_file or args.out_yaml_file))) or args.A:
        args.A = True
    else:
        args.A = False

    # Only global variable which meant to be modified
    global_verbose = args.verbose

    if not valid_host(args.host):
        abort(1, f"Target {args.host} contains some illegal character. Exiting.")

    # Check Workgroup
    if args.workgroup:
        if not valid_workgroup(args.workgroup):
            abort(1, f"Workgroup {args.workgroup} contains some illegal character. Exiting.")

    # Check for RID ranges
    if not valid_rid_ranges(args.ranges):
        abort(1, "The given RID ranges should be like 10-20 or 1199. Exiting.")

    # Check shares file
    if args.shares_file:
        validation = valid_shares_file(args.shares_file)
        if not validation.retval:
            abort(1, validation.retmsg)

    return args

def check_dependencies():
    missing = []

    for dep in global_deps:
        if not shutil.which(dep):
            missing.append(dep)

    if missing:
        print_error(f"The following dependend programs are missing: {', '.join(missing)}")
        print_error('     For Gentoo, you need to install the "samba" package.')
        print_error('     For Debian derivates (like Ubuntu) or ArchLinux, you need to install the "smbclient" package.')
        abort(1, "Exiting.")

def main():
    print("ENUM4LINUX-NG")
    start_time = time()

    # Make sure yaml can handle OrdereDicts
    yaml.add_representer(OrderedDict, lambda dumper, data: dumper.represent_mapping('tag:yaml.org,2002:map', data.items()))
    check_dependencies()

    args = check_args(sys.argv[1:])
    if args.out_json_file:
        output = Output(args.out_json_file, "json")
    elif args.out_yaml_file:
        output = Output(args.out_yaml_file, "yaml")
    else:
        output = Output()

    creds = Credentials(args.user, args.pw)
    target = Target(args.host, args.workgroup)

    if args.R:
        rid_ranges = prepare_rid_ranges(args.ranges)
        cycle_params = RidCycleParams(rid_ranges, args.users)

    print_heading("Target Information")
    print_info(f"Target ........... {target.host}")
    print_info(f"Username ......... '{creds.user}'")
    print_info(f"Password ......... '{creds.pw}'")
    print_info(f"RID Range(s) ..... {args.ranges}")
    print_info(f"Known Usernames .. '{args.users}'")

    # Checks if host is a parent/child domain controller, try to get long domain name
    if args.L or args.A:
        result = run_module_ldapsearch(target, creds)
        output.update(result)

    # Try to retrieve workstation and nbtstat information
    if args.N or args.A:
        result = run_module_netbios(target, creds)
        if "workgroup" in result:
            target.workgroup = result["workgroup"]
        output.update(result)

    # Check for user credential and null sessions
    result = run_module_session_check(target, creds)
    output.update(result)
    if not output.as_dict()['sessions_possible']:
        abort(1, "Server doesn't allow sessions. Aborting remainder of tests.")

    # Try to get domain name and sid via lsaquery
    result = run_module_lsaquery(target, creds)
    if "workgroup" in result:
        target.workgroup = result["workgroup"]
    output.update(result)

    # Get OS information like os version, server type string...
    if args.O or args.A:
        result = run_module_srvinfo(target, creds)
        output.update(result)

    # Enum users
    if args.U or args.A:
        result = run_module_enum_users(target, creds, args.d)
        output.update(result)

    # Enum groups
    if args.G or args.Gm or args.A:
        result = run_module_enum_groups(target, creds, args.Gm, args.d)
        output.update(result)

    # Enum shares
    if args.S or args.A:
        result = run_module_enum_shares(target, creds)
        output.update(result)

    # Enum password policy
    if args.P or args.A:
        result = run_module_enum_policy(target, creds)
        output.update(result)

    # Enum printers
    if args.I or args.A:
        result = run_module_enum_printers(target, creds)
        output.update(result)

    # RID Cycling (= bruteforce users, groups and machines)
    if args.R:
        for key in ["domain_sid", "users", "groups", "machines"]:
            if key in output.as_dict():
                cycle_params.enumerated_input[key] = output.as_dict()[key]
        result = run_module_rid_cycling(cycle_params, target, creds, args.d)
        output.update(result)

    # Brute force shares
    if args.shares_file:
        result = run_module_bruteforce_shares(args.file, target, creds)
        output.update(result)

    elapsed_time = time() - start_time
    print(f"\nCompleted after {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()
