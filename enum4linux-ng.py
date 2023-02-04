#!/usr/bin/env python3

# pylint: disable=C0301, E1101

### ENUM4LINUX-NG
# This tool is a rewrite of Mark Lowe's (former Portcullis Labs, now Cisco CX Security Labs ) enum4linux.pl,
# a tool for enumerating information from Windows and Samba systems.
# As the original enum4linux.pl, this tool is mainly a wrapper around the Samba tools 'nmblookup', 'net',
# 'rpcclient' and 'smbclient'. Other than the original enum4linux.pl, enum4linux-ng parses all output of
# the previously mentioned commands and (if the user requests so), fills the data in JSON/YAML output.
# The original enum4linux.pl had the additional dependencies 'ldapsearch' and 'polenum.py'. These are
# natively implemented in enum4linux-ng. Console output is colored (can be deactivated by setting the
# environment variable NO_COLOR to an arbitrary value).
#
### CREDITS
# I'd like to thank and give credit to the people at former Portcullis Labs (now Cisco CX Security Labs), namely:
#
# - Mark Lowe for creating the original 'enum4linux.pl'
#   https://github.com/CiscoCXSecurity/enum4linux
#
# - Richard "deanx" Dean for creating the original 'polenum'
#   https://labs.portcullis.co.uk/tools/polenum/
#
# In addition, I'd like to thank and give credit to:
# - Craig "Wh1t3Fox" West for his fork of 'polenum'
#   https://github.com/Wh1t3Fox/polenum
#
#
### DESIGN
#
# Error handling
# ==============
#
# * Functions:
#       * return value is None
#         => an error happened, error messages will be printed out and will end up in the JSON/YAML with value
#            null (see also YAML/JSON below)
#
#       * return value is an empty [],{},""
#         => no error, nothing was returned (e.g. a group has no members)
#
#       * return value is False for...
#         - sessions:
#         => it was not possible to set up the particular session with the target
#         - services:
#         => error, it was not possible to setup a service connection
#         - all other booleans:
#         => no errors
#
# * YAML/JSON:
#       * null
#         => an error happened (i.e. a function returned None which translates to null in JSON/YAML), in
#            this case an error message was generated and can be found under:
#            - 'errors', <key> for which the error happened (e.g. os_info), <module name> where the error occured
#            (e.g. module_srvinfo)
#
#       * missing key
#         => either it was not part of the enumeration because the user did not request it (aka did not provide
#            the right parameter when running enum4linux-ng)
#         => or it was part of the enumeration but no session could be set up (see above), in this case
#            - 'sessions', 'sessions_possible' should be 'False'
#
# Authentication
# ==============
# * Kerberos:
#       * While testing Kerberos authentication with the Samba client tools and the impacket library, it turned
#         out that they behave quite differently. While the impacket library will honor the username and the domain
#         given, it seems that the Samba client ignores them (-U and -W parameter) and uses the ones from the ticket
#         itself.
#
### LICENSE
# This tool may be used for legal purposes only. Users take full responsibility
# for any actions performed using this tool. The author accepts no liability
# for damage caused by this tool. If these terms are not acceptable to you, then
# you are not permitted to use this tool.
#
# In all other respects the GPL version 3 applies.
#
# The original enum4linux.pl was released under GPL version 2 or later.
# The original polenum.py was released under GPL version 3.

from argparse import ArgumentParser
from collections import OrderedDict
from datetime import datetime
import json
import os
import random
import re
import shutil
import shlex
import socket
from subprocess import check_output, STDOUT, TimeoutExpired
import sys
import tempfile
from impacket import nmb, smb, smbconnection, smb3
from impacket.smbconnection import SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_DIALECT_311
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5 import transport, samr
from ldap3 import Server, Connection, DSA
import yaml
try:
    from yaml import CDumper as Dumper
except ImportError:
    from yaml import Dumper

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
NBT_INFO = [
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
ACB_DICT = {
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
DOMAIN_FIELDS = {
        0x00000001: "DOMAIN_PASSWORD_COMPLEX",
        0x00000002: "DOMAIN_PASSWORD_NO_ANON_CHANGE",
        0x00000004: "DOMAIN_PASSWORD_NO_CLEAR_CHANGE",
        0x00000008: "DOMAIN_PASSWORD_LOCKOUT_ADMINS",
        0x00000010: "DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT",
        0x00000020: "DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE"
        }

# Source: https://docs.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
OS_VERSIONS = {
        "10.0": "Windows 10, Windows Server 2019, Windows Server 2016",
        "6.3": "Windows 8.1, Windows Server 2012 R2",
        "6.2": "Windows 8, Windows Server 2012",
        "6.1": "Windows 7, Windows Server 2008 R2",
        "6.0": "Windows Vista, Windows Server 2008",
        "5.2": "Windows XP 64-Bit Edition, Windows Server 2003, Windows Server 2003 R2",
        "5.1": "Windows XP",
        "5.0": "Windows 2000",
        }

# Source: https://docs.microsoft.com/de-de/windows/release-health/release-information
OS_RELEASE = {
        "19045": "22H2",
        "19044": "21H2",
        "19043": "21H1",
        "19042": "20H2",
        "19041": "2004",
        "18363": "1909",
        "18362": "1903",
        "17763": "1809",
        "17134": "1803",
        "16299": "1709",
        "15063": "1703",
        "14393": "1607",
        "10586": "1511",
        "10240": "1507"
        }

# Filter for various samba client setup related error messages including bug
# https://bugzilla.samba.org/show_bug.cgi?id=13925
SAMBA_CLIENT_ERRORS = [
        "Unable to initialize messaging context",
        "WARNING: no network interfaces found",
        "Can't load /etc/samba/smb.conf - run testparm to debug it"
    ]

# Translates various SMB dialect values to human readable strings
SMB_DIALECTS = {
        SMB_DIALECT: "SMB 1.0",
        SMB2_DIALECT_002: "SMB 2.02",
        SMB2_DIALECT_21: "SMB 2.1",
        SMB2_DIALECT_30: "SMB 3.0",
        SMB2_DIALECT_311: "SMB 3.1.1"
    }

# This list will be used by the function nt_status_error_filter() which is typically
# called after running a Samba client command (see run()). The idea is to filter out
# common errors. For very specific status errors, please don't handle them here but
# in the corresponding enumeration class/function.
# In the current implementation this list is case insensitive. Also the order of errors
# is important. Errors on top will be processed first. The access denied errors should
# be kept on top since they occur typically first (see also comment on
# STATUS_CONNECTION_DISCONNECTED).
NT_STATUS_COMMON_ERRORS = [
        "RPC_S_ACCESS_DENIED",
        "DCERPC_FAULT_ACCESS_DENIED",
        "WERR_ACCESS_DENIED",
        "STATUS_ACCESS_DENIED",
        "STATUS_ACCOUNT_LOCKED_OUT",
        "STATUS_NO_LOGON_SERVERS",
        "STATUS_LOGON_FAILURE",
        "STATUS_IO_TIMEOUT",
        "STATUS_NETWORK_UNREACHABLE",
        "STATUS_INVALID_PARAMETER",
        "STATUS_NOT_SUPPORTED",
        "STATUS_NO_SUCH_FILE",
        "STATUS_PASSWORD_EXPIRED",
        # This error code is from the depths of CIFS/SMBv1
        # https://tools.ietf.org/id/draft-leach-cifs-v1-spec-01.txt
        "ERRSRV:ERRaccess",
        # This error is misleading. It can occur when the an SMB client cannot negotiate
        # a connection with the SMB server e.g., because of both not supporting each others
        # SMB dialect. But this error can also occur if during an RPC call access was denied
        # to a specific ressource/function call. In this case the oppositve site often disconnects
        # and the Samba client tools will show this error.
        "STATUS_CONNECTION_DISCONNECTED"
    ]

# Supported authentication methods
AUTH_PASSWORD = "password"
AUTH_NTHASH = "nthash"
AUTH_KERBEROS = "kerberos"
AUTH_NULL = "null"

# Mapping from errno to string for socket errors we often come across
SOCKET_ERRORS = {
        11: "timed out",
        110: "timed out",
        111: "connection refused",
        113: "no route to host"
        }

# This is needed for the ListenersScan class
SERVICE_LDAP = "LDAP"
SERVICE_LDAPS = "LDAPS"
SERVICE_SMB = "SMB"
SERVICE_SMB_NETBIOS = "SMB over NetBIOS"
SERVICES = {
        SERVICE_LDAP: 389,
        SERVICE_LDAPS: 636,
        SERVICE_SMB: 445,
        SERVICE_SMB_NETBIOS: 139
        }

# The current list of module names
ENUM_LDAP_DOMAIN_INFO = "enum_ldap_domain_info"
ENUM_NETBIOS = "enum_netbios"
ENUM_SMB = "enum_smb"
ENUM_SESSIONS = "enum_sessions"
ENUM_SMB_DOMAIN_INFO = "enum_smb_domain_info"
ENUM_LSAQUERY_DOMAIN_INFO = "enum_lsaquery_domain_info"
ENUM_USERS_RPC = "enum_users_rpc"
ENUM_GROUPS_RPC = "enum_groups_rpc"
ENUM_SHARES = "enum_shares"
ENUM_SERVICES = "enum_services"
ENUM_LISTENERS = "enum_listeners"
ENUM_POLICY = "enum_policy"
ENUM_PRINTERS = "enum_printers"
ENUM_OS_INFO = "enum_os_info"
RID_CYCLING = "rid_cycling"
BRUTE_FORCE_SHARES = "brute_force_shares"

DEPS = ["nmblookup", "net", "rpcclient", "smbclient"]
RID_RANGES = "500-550,1000-1050"
KNOWN_USERNAMES = "administrator,guest,krbtgt,domain admins,root,bin,none"
TIMEOUT = 5

GLOBAL_VERSION = '1.3.1'
GLOBAL_VERBOSE = False
GLOBAL_COLORS = True
GLOBAL_SAMBA_LEGACY = False

class Colors:
    ansi_reset = '\033[0m'
    ansi_red = '\033[91m'
    ansi_green = '\033[92m'
    ansi_yellow = '\033[93m'
    ansi_blue = '\033[94m'

    @classmethod
    def red(cls, msg):
        if GLOBAL_COLORS:
            return f"{cls.ansi_red}{msg}{cls.ansi_reset}"
        return msg

    @classmethod
    def green(cls, msg):
        if GLOBAL_COLORS:
            return f"{cls.ansi_green}{msg}{cls.ansi_reset}"
        return msg

    @classmethod
    def yellow(cls, msg):
        if GLOBAL_COLORS:
            return f"{cls.ansi_yellow}{msg}{cls.ansi_reset}"
        return msg

    @classmethod
    def blue(cls, msg):
        if GLOBAL_COLORS:
            return f"{cls.ansi_blue}{msg}{cls.ansi_reset}"
        return msg

class Result:
    '''
    The idea of the Result class is, that functions can easily return a return value
    as well as a return message. The return message can be further processed or printed
    out by the calling function, while the return value is supposed to be added to the
    output dictionary (contained in class Output), which will be later converted to JSON/YAML.
    '''
    def __init__(self, retval, retmsg):
        self.retval = retval
        self.retmsg = retmsg

class Target:
    '''
    Target encapsulates various target information. The class should only be instantiated once and
    passed during the enumeration to the various modules. This allows to modify/update target information
    during enumeration.
    '''
    def __init__(self, host, credentials, port=None, tls=None, timeout=None, samba_config=None, sessions={}):
        self.host = host
        self.creds = credentials
        self.port = port
        self.timeout = timeout
        self.tls = tls
        self.samba_config = samba_config
        self.sessions = sessions

        self.ip_version = None
        self.smb_ports = []
        self.ldap_ports = []
        self.listeners = []
        self.smb_preferred_dialect = None
        self.smb1_supported = False
        self.smb1_only = False

        result = self.valid_host(host)
        if not result.retval:
            raise Exception(result.retmsg)

    def valid_host(self, host):
        try:
            result = socket.getaddrinfo(host, None)

            # Check IP version, alternatively we could save the socket type here
            ip_version = result[0][0]
            if ip_version == socket.AF_INET6:
                self.ip_version = 6
            elif ip_version == socket.AF_INET:
                self.ip_version = 4

            # Kerberos requires resolvable hostnames rather than IP adresses
            ip = result[0][4][0]
            if ip == host and self.creds.auth_method == AUTH_KERBEROS:
                return Result(False, f'Kerberos authentication requires a hostname, but an IPv{self.ip_version} address was given')

            return Result(True,'')
        except Exception as e:
            if isinstance(e, OSError) and e.errno == -2:
                return Result(False, f'Could not resolve host {host}')
        return Result(False, 'No valid host given')

    def as_dict(self):
        return {'target':{'host':self.host}}

class Credentials:
    '''
    Stores usernames and password.
    '''
    def __init__(self, user='', pw='', domain='', ticket_file='', nthash='', local_auth=False):
        # Create an alternative user with pseudo-random username
        self.random_user = ''.join(random.choice("abcdefghijklmnopqrstuvwxyz") for i in range(8))
        self.user = user
        self.pw = pw
        self.ticket_file = ticket_file
        self.nthash = nthash
        self.local_auth = local_auth

        # Only set the domain here, if it is not empty
        self.domain = ''
        if domain:
            self.set_domain(domain)

        if ticket_file:
            result = self.valid_ticket(ticket_file)
            if not result.retval:
                raise Exception(result.retmsg)
            self.auth_method = AUTH_KERBEROS
        elif nthash:
            result = self.valid_nthash(nthash)
            if not result.retval:
                raise Exception(result.retmsg)
            if nthash and not user:
                raise Exception("NT hash given (-H) without any user, please provide a username (-u)")
            self.auth_method = AUTH_NTHASH
        elif not user and not pw:
            self.auth_method = AUTH_NULL
        else:
            if pw and not user:
                raise Exception("Password given (-p) without any user, please provide a username (-u)")
            self.auth_method = AUTH_PASSWORD

    def valid_nthash(self, nthash):
        hash_len = len(nthash)
        if hash_len != 32:
            return Result(False, f'The given hash has {hash_len} characters instead of 32 characters')
        if not re.match(r"^[a-fA-F0-9]{32}$", nthash):
            return Result(False, f'The given hash contains invalid characters')
        return Result(True, '')

    def valid_ticket(self, ticket_file):
        return valid_file(ticket_file)

    # Allows various modules to set the domain during enumeration. The domain can only be set once.
    # Currently, we rely on the information gained via unauth smb session to guess the domain.
    # At a later call of lsaquery it might turn out that the domain is different. In this case the
    # user will be informed via print_hint()
    def set_domain(self, domain):
        if self.domain and self.domain.lower() == domain.lower():
            return True
        if not self.domain:
            self.domain = domain
            return True
        return False

    def as_dict(self):
        return {'credentials':OrderedDict({'auth_method':self.auth_method, 'user':self.user, 'password':self.pw, 'domain':self.domain, 'ticket_file':self.ticket_file, 'nthash':self.nthash, 'random_user':self.random_user})}

class SmbConnection():
    def __init__(self, target, creds=Credentials(), dialect=None):
        self.target = target
        self.creds = creds
        self.dialect = dialect
        self._conn = None

        self.connect()

    def connect(self):
        self._conn = smbconnection.SMBConnection(self.target.host, self.target.host, sess_port=self.target.port, timeout=self.target.timeout, preferredDialect=self.dialect)

    def login(self):
        creds = self.creds

        # Take a backup of the environment, in case we modify it for Kerberos
        env = os.environ.copy()
        try:
            if creds.ticket_file:
                # Currently we let impacket extract user and domain from the ticket
                os.environ['KRB5CCNAME'] = creds.ticket_file
                self._conn.kerberosLogin('', creds.pw, domain='', useCache=True)
            elif creds.nthash:
                self._conn.login(creds.user, creds.pw, domain=creds.domain, nthash=creds.nthash)
            else:
                self._conn.login(creds.user, creds.pw, creds.domain)
        except Exception as e:
            #FIXME: Might need adjustment
            return Result((None, None), process_impacket_smb_exception(e, self.target))
        finally:
            # Restore environment in any case
            os.environ.clear()
            os.environ.update(env)

    def close(self):
        self._conn.close()

    def get_dialect(self):
        return self._conn.getDialect()

    def is_signing_required(self):
        return self._conn.isSigningRequired()

    def get_raw(self):
        return self._conn

    def get_server_lanman(self):
        return self._conn.getSMBServer().get_server_lanman()

    def get_server_os(self):
        return self._conn.getSMBServer().get_server_os()

    def get_server_os_major(self):
        return self._conn.getServerOSMajor()

    def get_server_os_minor(self):
        return self._conn.getServerOSMinor()

    def get_server_os_build(self):
        return self._conn.getServerOSBuild()

    def get_server_domain(self):
        return self._conn.getServerDomain()

    def get_server_name(self):
        return self._conn.getServerName()

    def get_server_dns_hostname(self):
        return self._conn.getServerDNSHostName()

    def get_server_dns_domainname(self):
        return self._conn.getServerDNSDomainName()

class DceRpc():
    def __init__(self, smb_conn):
        self._smb_conn = smb_conn
        self.dce = None
        self.filename = None
        self.msrpc_uuid = None

        if isinstance(self, SAMR):
            self.filename = r'\samr'
            self.msrpc_uuid = samr.MSRPC_UUID_SAMR

        self._connect()

    def _connect(self):
        rpctransport = transport.SMBTransport(smb_connection=self._smb_conn.get_raw(), filename=self.filename, remoteName=self._smb_conn.target.host)
        self.dce = DCERPC_v5(rpctransport)
        self.dce.connect()
        self.dce.bind(self.msrpc_uuid)

class SAMR(DceRpc):
    def __init__(self, smb_conn=None):
        super().__init__(smb_conn)

        self._server_handle = self._get_server_handle()

    def _get_server_handle(self):
        resp = samr.hSamrConnect(self.dce)
        return resp['ServerHandle']

    def get_domains(self):
        resp = samr.hSamrEnumerateDomainsInSamServer(self.dce, self._server_handle)
        domains = resp['Buffer']['Buffer']
        domain_names = []
        for domain in domains:
            domain_names.append(domain['Name'])
        return domain_names

    def get_domain_handle(self, domain_name):
        resp = samr.hSamrLookupDomainInSamServer(self.dce, self._server_handle, domain_name)
        resp = samr.hSamrOpenDomain(self.dce, serverHandle = self._server_handle, domainId = resp['DomainId'])
        return resp['DomainHandle']

    def get_domain_password_information(self, domain_handle):
        resp = samr.hSamrQueryInformationDomain2(self.dce, domainHandle=domain_handle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        return resp['Buffer']['Password']

    def get_domain_lockout_information(self, domain_handle):
        resp = samr.hSamrQueryInformationDomain2(self.dce, domainHandle=domain_handle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
        return resp['Buffer']['Lockout']

    def get_domain_logoff_information(self, domain_handle):
        resp = samr.hSamrQueryInformationDomain2(self.dce, domainHandle=domain_handle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation)
        return resp['Buffer']['Logoff']

    def query_display_information(self, domain_handle):
        resp = samr.hSamrQueryDisplayInformation(self.dce, domainHandle=domain_handle)
        return resp['Buffer']['UserInformation']['Buffer']

class SambaTool():
    '''
    Encapsulates various Samba Tools.
    '''

    def __init__(self, command, target, creds):
        self.target = target
        self.creds = creds
        self.env = None

        # This list stores the various parts of the command which will be later executed by run().
        self.exec = []

        # Set authentication method
        if self.creds:
            if creds.ticket_file:
                # Set KRB5CCNAME as environment variable and let it point to the ticket.
                # The environment will be later passed to check_output() (see run() below).
                self.env = os.environ.copy()
                self.env['KRB5CCNAME'] = self.creds.ticket_file
                # User and domain are taken from the ticket
                # Kerberos options differ between samba versions - TODO: Can be removed in the future
                if GLOBAL_SAMBA_LEGACY:
                    self.exec += ['-k']
                else:
                    self.exec += ['--use-krb5-ccache', self.creds.ticket_file]
            elif creds.nthash:
                self.exec += ['-W', f'{self.creds.domain}']
                self.exec += ['-U', f'{self.creds.user}%{self.creds.nthash}', '--pw-nt-hash']
            else:
                self.exec += ['-W', f'{self.creds.domain}']
                self.exec += ['-U', f'{self.creds.user}%{self.creds.pw}']

        # If the target has a custom Samba configuration attached, we will add it to the
        # command. This allows to modify the behaviour of the samba client commands during
        # run (e.g. enforce legacy SMBv1).
        if target.samba_config:
            self.exec += ['-s', f'{target.samba_config.get_path()}']

        # This enables debugging output (level 1) for the Samba client tools. The problem is that the
        # tools often throw misleading error codes like NT_STATUS_CONNECTION_DISCONNECTED. Often this
        # error is associated with SMB dialect incompatibilities between client and server. But this
        # error also occurs on other occasions. In order to find out the real reason we need to fetch
        # earlier errors which this debugging level will provide.
        #self.exec += ['-d1']

    def run(self, log, error_filter=True):
        '''
        Runs a samba client command (net, nmblookup, smbclient or rpcclient) and does some basic output filtering.
        '''

        if GLOBAL_VERBOSE and log:
            print_verbose(f"{log}, running command: {' '.join(shlex.quote(x) for x in self.exec)}")

        try:
            output = check_output(self.exec, env=self.env, shell=False, stderr=STDOUT, timeout=self.target.timeout)
            retval = 0
        except TimeoutExpired:
            return Result(False, "timed out")
        except Exception as e:
            output = e.output
            retval = 1

        output = output.decode()
        for line in output.splitlines(True):
            if any(entry in line for entry in SAMBA_CLIENT_ERRORS):
                output = output.replace(line, "")
        output = output.rstrip('\n')

        if "Cannot find KDC for realm" in output:
            return Result(False, "Cannot find KDC for realm, check DNS settings or setup /etc/krb5.conf")

        if retval == 1 and not output:
            return Result(False, "empty response")

        if error_filter:
            nt_status_error = nt_status_error_filter(output)
            if nt_status_error:
                return Result(False, nt_status_error)

        return Result(True, output)

class SambaSmbclient(SambaTool):
    '''
    Encapsulates a subset of the functionality of the Samba smbclient command.
    '''
    def __init__(self, command, target, creds):
        super().__init__(command, target, creds)

        # Set timeout
        self.exec += ['-t', f'{target.timeout}']

        # Build command
        if command[0] == 'list':
            self.exec += ['-L', f'//{target.host}', '-g']
        elif command[0] == 'help':
            self.exec += ['-c','help', f'//{target.host}/ipc$']
        elif command[0] == 'dir' and command[1]:
            self.exec += ['-c','dir', f'//{target.host}/{command[1]}']

        self.exec = ['smbclient'] + self.exec

class SambaRpcclient(SambaTool):
    '''
    Encapsulates a subset of the functionality of the Samba rpcclient command.
    '''
    def __init__(self, command, target, creds):
        super().__init__(command, target, creds)

        # Build command
        if command[0] == 'queryuser':
            rid = command[1]
            self.exec += ['-c', f'{command[0]} {rid}']
        elif command[0] == 'querygroup':
            rid = command[1]
            self.exec += ['-c', f'{command[0]} {rid}']
        elif command[0] == 'enumalsgroups':
            group_type = command[1]
            self.exec += ['-c', f'{command[0]} {group_type}']
        elif command[0] == 'lookupnames':
            username = command[1]
            self.exec += ['-c', f'{command[0]} {username}']
        elif command[0] == 'lookupsids':
            sid = command[1]
            self.exec += ['-c', f'{command[0]} {sid}']
        # Currently, here the following commands should be handled:
        # enumprinters
        # enumdomusers, enumdomgroups
        # lsaenumsid, lsaquery
        # querydispinfo
        # srvinfo
        else:
            self.exec += ['-c', f'{command[0]}']

        self.exec += [ target.host ]
        self.exec = ['rpcclient'] + self.exec

class SambaNet(SambaTool):
    '''
    Encapsulates a subset of the functionality of the Samba net command.
    '''
    def __init__(self, command, target, creds):
        super().__init__(command, target, creds)

        # Set timeout
        self.exec += ['-t', f'{target.timeout}']

        # Build command
        if command[0] == 'rpc':
            if command[1] == 'group':
                if command[2] == 'members':
                    groupname = command[3]
                    self.exec += [f'{command[0]}', f'{ command[1]}', f'{command[2]}', groupname]
            if command[1] == 'service':
                if command[2] == 'list':
                    self.exec += [f'{command[0]}', f'{ command[1]}', f'{command[2]}']

        self.exec += [ "-S", target.host ]
        self.exec = ['net'] + self.exec

class SambaNmblookup(SambaTool):
    '''
    Encapsulates the nmblookup command. Currently only the -A option is supported.
    '''
    def __init__(self, target):
        super().__init__(None, target, creds=None)

        self.exec += [ "-A", target.host ]
        self.exec = ['nmblookup'] + self.exec

class SambaConfig:
    '''
    Allows to create custom Samba configurations which can be passed via path to the various Samba client tools.
    Currently such a configuration is always created on tool start. This allows to overcome issues with newer
    releases of the Samba client tools where certain features are disabled by default.
    '''
    def __init__(self, entries):
        config = '\n'.join(['[global]']+entries) + '\n'
        with tempfile.NamedTemporaryFile(delete=False) as config_file:
            config_file.write(config.encode())
            self.config_filename = config_file.name

    def get_path(self):
        return self.config_filename

    def add(self, entries):
        try:
            config = '\n'.join(entries) + '\n'
            with open(self.config_filename, 'a') as config_file:
                config_file.write(config)
            return True
        except:
            return False

    def delete(self):
        try:
            os.remove(self.config_filename)
        except OSError:
            return Result(False, f"Could not delete samba configuration file {self.config_filename}")
        return Result(True, "")

class Output:
    '''
    Output stores the output dictionary which will be filled out during the run of
    the tool. The update() function takes a dictionary, which will then be merged
    into the output dictionary (out_dict). In addition, the update() function is
    responsible for writing the JSON/YAML output.
    '''
    def __init__(self, out_file=None, out_file_type=None):
        self.out_file = out_file
        self.out_file_type = out_file_type
        self.out_dict = OrderedDict({"errors":{}})

    def update(self, content):
        # The following is needed, since python3 does not support nested merge of
        # dictionaries out of the box:

        # Temporarily save the current "errors" sub dict. Then update out_dict with the new
        # content. If "content" also had an "errors" dict (e.g. if the module run failed),
        # this would overwrite the "errors" dict from the previous run. Therefore,
        # we replace the old out_dict["errors"] with the saved one. A proper merge will
        # then be done further down.
        old_errors_dict = self.out_dict["errors"]
        self.out_dict.update(content)
        self.out_dict["errors"] = old_errors_dict

        # Merge dicts
        if "errors" in content:
            new_errors_dict = content["errors"]

            for key, value in new_errors_dict.items():
                if key in old_errors_dict:
                    self.out_dict["errors"][key] = {**old_errors_dict[key], **new_errors_dict[key]}
                else:
                    self.out_dict["errors"][key] = value

    def flush(self):
        # Only for nice JSON/YAML output (errors at the end)
        self.out_dict.move_to_end("errors")

        # Write JSON/YAML
        if self.out_file is not None:
            if "json" in self.out_file_type and not self._write_json():
                return Result(False, f"Could not write JSON output to {self.out_file}.json")
            if "yaml" in self.out_file_type and not self._write_yaml():
                return Result(False, f"Could not write YAML output to {self.out_file}.yaml")
        return Result(True, "")

    def _write_json(self):
        try:
            with open(f"{self.out_file}.json", 'w') as f:
                f.write(json.dumps(self.out_dict, indent=4))
        except OSError:
            return False
        return True

    def _write_yaml(self):
        try:
            with open(f"{self.out_file}.yaml", 'w') as f:
                f.write(yamlize(self.out_dict, rstrip=False))
        except OSError:
            return False
        return True

    def as_dict(self):
        return self.out_dict

### Listeners Scans

class ListenersScan():
    def __init__(self, target, scan_list):
        self.target = target
        self.scan_list = scan_list
        self.listeners = OrderedDict({})

    def run(self):
        module_name = ENUM_LISTENERS
        output = {}

        print_heading(f"Listener Scan on {self.target.host}")
        for listener, port in SERVICES.items():
            if listener not in self.scan_list:
                continue

            print_info(f"Checking {listener}")
            result = self.check_accessible(listener, port)
            if result.retval:
                print_success(result.retmsg)
            else:
                output = process_error(result.retmsg, ["listeners"], module_name, output)

            self.listeners[listener] = {"port": port, "accessible": result.retval}

        output["listeners"] = self.listeners

        return output

    def check_accessible(self, listener, port):
        if self.target.ip_version == 6:
            address_family = socket.AF_INET6
        elif self.target.ip_version == 4:
            address_family = socket.AF_INET

        try:
            sock = socket.socket(address_family, socket.SOCK_STREAM)
            sock.settimeout(self.target.timeout)
            result = sock.connect_ex((self.target.host, port))
            if result == 0:
                return Result(True, f"{listener} is accessible on {port}/tcp")
            return Result(False, f"Could not connect to {listener} on {port}/tcp: {SOCKET_ERRORS[result]}")
        except Exception:
            return Result(False, f"Could not connect to {listener} on {port}/tcp")

    def get_accessible_listeners(self):
        accessible = []
        for listener, entry in self.listeners.items():
            if entry["accessible"] is True:
                accessible.append(listener)
        return accessible

    def get_accessible_ports_by_pattern(self, pattern):
        accessible = []
        for listener, entry in self.listeners.items():
            if pattern in listener and entry["accessible"] is True:
                accessible.append(entry["port"])
        return accessible

### NetBIOS Enumeration

class EnumNetbios():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run NetBIOS module which collects Netbios names and the workgroup/domain.
        '''
        module_name = ENUM_NETBIOS
        print_heading(f"NetBIOS Names and Workgroup/Domain for {self.target.host}")
        output = {"domain":None, "nmblookup":None}

        nmblookup = self.nmblookup()
        if nmblookup.retval:
            result = self.get_domain(nmblookup.retval)
            if result.retval:
                print_success(result.retmsg)
                output["domain"] = result.retval
            else:
                output = process_error(result.retmsg, ["domain"], module_name, output)

            result = self.nmblookup_to_human(nmblookup.retval)
            print_success(result.retmsg)
            output["nmblookup"] = result.retval
        else:
            output = process_error(nmblookup.retmsg, ["nmblookup", "domain"], module_name, output)

        return output

    def nmblookup(self):
        '''
        Runs nmblookup (a NetBIOS over TCP/IP Client) in order to lookup NetBIOS names information.
        '''

        result = SambaNmblookup(self.target).run(log='Trying to get NetBIOS names information')

        if not result.retval:
            return Result(None, f"Could not get NetBIOS names information via 'nmblookup': {result.retmsg}")

        if "No reply from" in result.retmsg:
            return Result(None, "Could not get NetBIOS names information via 'nmblookup': host does not reply")

        return Result(result.retmsg, "")

    def get_domain(self, nmblookup_result):
        '''
        Extract domain from given nmblookoup result.
        '''
        match = re.search(r"^\s+(\S+)\s+<00>\s+-\s+<GROUP>\s+", nmblookup_result, re.MULTILINE)
        if match:
            if valid_domain(match.group(1)):
                domain = match.group(1)
            else:
                return Result(None, f"Workgroup {domain} contains some illegal characters")
        else:
            return Result(None, "Could not find domain/domain")

        if not self.creds.local_auth:
            self.creds.set_domain(domain)
        return Result(domain, f"Got domain/workgroup name: {domain}")

    def nmblookup_to_human(self, nmblookup_result):
        '''
        Map nmblookup output to human readable strings.
        '''
        output = []
        nmblookup_result = nmblookup_result.splitlines()
        for line in nmblookup_result:
            if "Looking up status of" in line or line == "":
                continue

            line = line.replace("\t", "")
            match = re.match(r"^(\S+)\s+<(..)>\s+-\s+?(<GROUP>)?\s+?[A-Z]", line)
            if match:
                line_val = match.group(1)
                line_code = match.group(2).upper()
                line_group = not match.group(3)
                for entry in NBT_INFO:
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
        return Result(output, f"Full NetBIOS names information:\n{yamlize(output)}")

### SMB checks

class EnumSmb():
    def __init__(self, target, detailed):
        self.target = target
        self.detailed = detailed

    def run(self):
        '''
        Run SMB module which checks for the supported SMB dialects.
        '''
        module_name = ENUM_SMB
        print_heading(f"SMB Dialect Check on {self.target.host}")
        output = {}

        for port in self.target.smb_ports:
            print_info(f"Trying on {port}/tcp")
            self.target.port = port
            result = self.check_smb_dialects()
            if result.retval is None:
                output = process_error(result.retmsg, ["smb1_only"], module_name, output)
            else:
                output["smb_dialects"] = result.retval
                print_success(result.retmsg)
                break

        # Does the target only support SMBv1? Then enforce it!
        if result.retval and result.retval["SMB1 only"]:
            print_info("Enforcing legacy SMBv1 for further enumeration")
            result = self.enforce_smb1()
            if not result.retval:
                output = process_error(result.retmsg, ["smb_dialects"], module_name, output)

        output["smb_dialects"] = result.retval
        return output

    def enforce_smb1(self):
        try:
            if self.target.samba_config.add(['client min protocol = NT1']):
                return Result(True, "")
        except:
            pass
        return Result(False, "Could not enforce SMBv1")

    def check_smb_dialects(self):
        '''
        Current implementations of the samba client tools will enforce at least SMBv2 by default. This will give false
        negatives during session checks, if the target only supports SMBv1. Therefore, we try to find out here whether
        the target system only speaks SMBv1.
        '''
        supported = {
                SMB_DIALECTS[SMB_DIALECT]: False,
                SMB_DIALECTS[SMB2_DIALECT_002]: False,
                SMB_DIALECTS[SMB2_DIALECT_21]:False,
                SMB_DIALECTS[SMB2_DIALECT_30]:False,
                SMB_DIALECTS[SMB2_DIALECT_311]:False,
                }

        output = {
                "Supported dialects": None,
                "Preferred dialect": None,
                "SMB1 only": False,
                "SMB signing required": None
        }

        # List dialects supported by impacket
        smb_dialects = [SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_DIALECT_311]

        # Check all dialects
        last_supported_dialect = None
        for dialect in smb_dialects:
            try:
                smb_conn = SmbConnection(self.target, dialect=dialect)
                smb_conn.close()
                supported[SMB_DIALECTS[dialect]] = True
                last_supported_dialect = dialect
            except Exception:
                pass

        # Set whether we suppot SMB1 or not for this class
        self.target.smb1_supported = supported[SMB_DIALECTS[SMB_DIALECT]]

        # Does the target only support one dialect? Then this must be also the preferred dialect.
        preferred_dialect = None
        if sum(1 for value in supported.values() if value is True) == 1:
            if last_supported_dialect == SMB_DIALECT:
                output["SMB1 only"] = True
                self.target.smb1_only = True
            preferred_dialect = last_supported_dialect

        try:
            smb_conn = SmbConnection(self.target, dialect=preferred_dialect)
            preferred_dialect = smb_conn.get_dialect()
            # Check whether SMB signing is required or optional - since this seems to be a global setting, we check it only for the preferred dialect
            output["SMB signing required"] = smb_conn.is_signing_required()
            smb_conn.close()

            output["Preferred dialect"] = SMB_DIALECTS[preferred_dialect]
            self.target.smb_preferred_dialect = preferred_dialect
        except Exception as exc:
            # FIXME: This can propably go as impacket now supports SMB3 up to 3.11.
            if isinstance(exc, (smb3.SessionError)):
                if nt_status_error_filter(str(exc)) == "STATUS_NOT_SUPPORTED":
                    output["Preferred Dialect"] = "> SMB 3.0"

        output["Supported dialects"] = supported

        # When we end up here, a preferred dialect must have been set. If this is still set to None,
        # we can conclude that the target does not support any dialect at all.
        if not output["Preferred dialect"]:
            return Result(None, f"No supported dialects found")
        return Result(output, f"Supported dialects and settings:\n{yamlize(output)}")

### Session Checks

class EnumSessions():
    SESSION_USER = "user"
    SESSION_RANDOM = "random user"
    SESSION_NULL = "null"
    SESSION_KERBEROS="Kerberos"
    SESSION_NTHASH="NT hash"

    def __init__(self, target, creds):

        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run session check module which tests for user and null sessions.
        '''
        module_name = ENUM_SESSIONS
        print_heading(f"RPC Session Check on {self.target.host}")
        output = { "sessions":None }
        sessions = {"sessions_possible":False,
                  AUTH_NULL:False,
                  AUTH_PASSWORD:False,
                  AUTH_KERBEROS:False,
                  AUTH_NTHASH:False,
                  "random_user":False,
                  }

        # Check null session
        print_info("Check for null session")
        null_session = self.check_session(Credentials('', '', self.creds.domain), self.SESSION_NULL)
        if null_session.retval:
            sessions[AUTH_NULL] = True
            print_success(null_session.retmsg)
        else:
            output = process_error(null_session.retmsg, ["sessions"], module_name, output)

        # Check Kerberos session
        if self.creds.ticket_file:
            print_info("Check for Kerberos session")
            kerberos_session = self.check_session(self.creds, self.SESSION_KERBEROS)
            if kerberos_session.retval:
                sessions[AUTH_KERBEROS] = True
                print_success(kerberos_session.retmsg)
            else:
                output = process_error(kerberos_session.retmsg, ["sessions"], module_name, output)
        # Check NT hash session
        elif self.creds.nthash:
            print_info("Check for NT hash session")
            nthash_session = self.check_session(self.creds, self.SESSION_NTHASH)
            if nthash_session.retval:
                sessions[AUTH_NTHASH] = True
                print_success(nthash_session.retmsg)
            else:
                output = process_error(nthash_session.retmsg, ["sessions"], module_name, output)
        # Check for user session
        elif self.creds.user:
            print_info("Check for user session")
            user_session = self.check_session(self.creds, self.SESSION_USER)
            if user_session.retval:
                sessions[AUTH_PASSWORD] = True
                print_success(user_session.retmsg)
            else:
                output = process_error(user_session.retmsg, ["sessions"], module_name, output)

        # Check random user session
        print_info("Check for random user")
        user_session = self.check_session(Credentials(self.creds.random_user, self.creds.pw, self.creds.domain), self.SESSION_RANDOM)
        if user_session.retval:
            sessions["random_user"] = True
            print_success(user_session.retmsg)
            print_hint(f"Rerunning enumeration with user '{self.creds.random_user}' might give more results")
        else:
            output = process_error(user_session.retmsg, ["sessions"], module_name, output)

        if sessions[AUTH_NULL] or \
            sessions[AUTH_PASSWORD] or \
            sessions[AUTH_KERBEROS] or \
            sessions[AUTH_NTHASH] or \
            sessions["random_user"]:
            sessions["sessions_possible"] = True
        else:
            process_error("Sessions failed, neither null nor user sessions were possible", ["sessions"], module_name, output)

        output['sessions'] = sessions
        return output

    def check_session(self, creds, session_type):
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

        result = SambaSmbclient(['help'], self.target, creds).run(log='Attempting to make session')

        if not result.retval:
            return Result(False, f"Could not establish {session_type} session: {result.retmsg}")

        if "case_sensitive" in result.retmsg:
            if session_type == self.SESSION_KERBEROS:
                return Result(True, f"Server allows Kerberos session using '{creds.ticket_file}'")
            if session_type == self.SESSION_NTHASH:
                return Result(True, f"Server allows NT hash session using '{creds.nthash}'")
            return Result(True, f"Server allows session using username '{creds.user}', password '{creds.pw}'")
        return Result(False, f"Could not establish session using '{creds.user}', password '{creds.pw}'")

### Domain Information Enumeration via LDAP

class EnumLdapDomainInfo():
    def __init__(self, target):
        self.target = target

    def run(self):
        '''
        Run ldapsearch module which tries to find out whether host is a parent or
        child DC. Also tries to fetch long domain name. The information are get from
        the LDAP RootDSE.
        '''
        module_name = ENUM_LDAP_DOMAIN_INFO
        print_heading(f"Domain Information via LDAP for {self.target.host}")
        output = {"is_parent_dc":None,
                  "is_child_dc":None,
                  "long_domain":None}

        for with_tls in [False, True]:
            if with_tls:
                if SERVICES[SERVICE_LDAPS] not in self.target.ldap_ports:
                    continue
                print_info('Trying LDAPS')
            else:
                if SERVICES[SERVICE_LDAP] not in self.target.ldap_ports:
                    continue
                print_info('Trying LDAP')
            self.target.tls = with_tls
            namingcontexts = self.get_namingcontexts()
            if namingcontexts.retval is not None:
                break
            output = process_error(namingcontexts.retmsg, ["is_parent_dc", "is_child_dc", "long_domain"], module_name, output)

        if namingcontexts.retval:
            # Parent/root or child DC?
            result = self.check_parent_dc(namingcontexts.retval)
            if result.retval:
                output["is_parent_dc"] = True
                output["is_child_dc"] = False
            else:
                output["is_parent_dc"] = True
                output["is_child_dc"] = False
            print_success(result.retmsg)

            # Try to get long domain from ldapsearch result
            result = self.get_long_domain(namingcontexts.retval)
            if result.retval:
                print_success(result.retmsg)
                output["long_domain"] = result.retval
            else:
                output = process_error(result.retmsg, ["long_domain"], module_name, output)

        return output

    def get_namingcontexts(self):
        '''
        Tries to connect to LDAP/LDAPS. If successful, it tries to get the naming contexts from
        the so called Root Directory Server Agent Service Entry (RootDSE).
        '''
        try:
            server = Server(self.target.host, use_ssl=self.target.tls, get_info=DSA, connect_timeout=self.target.timeout)
            ldap_con = Connection(server, auto_bind=True)
            ldap_con.unbind()
        except Exception as e:
            if len(e.args) == 1:
                error = str(e.args[0])
            else:
                error = str(e.args[1][0][0])
            if "]" in error:
                error = error.split(']', 1)[1]
            elif ":" in error:
                error = error.split(':', 1)[1]
            error = error.lstrip().rstrip()
            if self.target.tls:
                return Result(None, f"LDAPS connect error: {error}")
            return Result(None, f"LDAP connect error: {error}")

        try:
            if not server.info.naming_contexts:
                return Result([], "NamingContexts are not readable")
        except Exception:
            return Result([], "NamingContexts are not readable")

        return Result(server.info.naming_contexts, "")

    def get_long_domain(self, namingcontexts_result):
        '''
        Tries to extract the long domain from the naming contexts.
        '''
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
        return Result(None, "Could not find long domain")

    def check_parent_dc(self, namingcontexts_result):
        '''
        Checks whether the target is a parent or child domain controller.
        This is done by searching for specific naming contexts.
        '''
        parent = False
        namingcontexts_result = '\n'.join(namingcontexts_result)
        if "DC=DomainDnsZones" in namingcontexts_result or "ForestDnsZones" in namingcontexts_result:
            parent = True
        if parent:
            return Result(True, "Appears to be root/parent DC")
        return Result(False, "Appears to be child DC")

### Domain Information Enumeration via (unauthenticated) SMB

class EnumSmbDomainInfo():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module EnumSmbDomainInfo  which extracts domain information from
        Session Setup Request packets.
        '''
        module_name = ENUM_SMB_DOMAIN_INFO
        print_heading(f"Domain Information via SMB session for {self.target.host}")
        output = {"smb_domain_info":None}

        for port in self.target.smb_ports:
            self.target.port = port
            print_info(f"Enumerating via unauthenticated SMB session on {port}/tcp")
            result_smb = self.enum_from_smb()
            if result_smb.retval:
                print_success(result_smb.retmsg)
                output["smb_domain_info"] = result_smb.retval
                break
            output = process_error(result_smb.retmsg, ["smb_domain_info"], module_name, output)

        return output

    def enum_from_smb(self):
        '''
        Tries to set up an SMB null session. Even if the null session does not succeed, the SMB protocol will transfer
        some information about the remote system in the SMB "Session Setup Response" or the SMB "Session Setup andX Response"
        packet. These are the domain, DNS domain name as well as DNS host name.
        '''
        smb_domain_info = {"NetBIOS computer name":None, "NetBIOS domain name":None, "DNS domain":None, "FQDN":None, "Derived membership":None, "Derived domain":None}

        smb_conn = None
        try:
            smb_conn = SmbConnection(self.target, Credentials(), dialect=self.target.smb_preferred_dialect)
            smb_conn.login()
        except Exception as e:
            error_msg = process_impacket_smb_exception(e, self.target)
            # STATUS_ACCESS_DENIED is the only error we can safely ignore. It basically tells us that a
            # null session is not allowed, but that is not an issue for our enumeration.
            if not "STATUS_ACCESS_DENIED" in error_msg:
                return Result(None, error_msg)

        # For SMBv1 we can typically find Domain in the "Session Setup AndX Response" packet.
        # For SMBv2 and later we find additional information like the DNS name and the DNS FQDN.
        try:
            smb_domain_info["NetBIOS domain name"] = smb_conn.get_server_domain()
            smb_domain_info["NetBIOS computer name"] = smb_conn.get_server_name()
            smb_domain_info["FQDN"] = smb_conn.get_server_dns_hostname().rstrip('\x00')
            smb_domain_info["DNS domain"] = smb_conn.get_server_dns_domainname().rstrip('\x00')
        except:
            pass

        # This is based on testing various Windows and Samba setups and might not be 100% correct.
        # The idea is that when we found a 'NetBIOS domain name' and the FQDN looks 'proper' we conclude
        # that the machine is a member of a domain (not a workgroup).
        # Very old Samba instances often only have the NetBIOS domain name set and nothing else. In this case,
        # the machine is a member of a workgroup with that name.
        # In all other cases, it can be concluded that the machine is a member of a workgroup. But that does not
        # mean that the 'NetBIOS domain name' is the same as the machine's workgroup. Therefore, we set the domain
        # to the 'NetBIOS computer name' which will enforce local authentication.

        if (smb_domain_info["NetBIOS computer name"] and
                smb_domain_info["NetBIOS domain name"] and
                smb_domain_info["DNS domain"] and
                smb_domain_info["FQDN"] and
                smb_domain_info["DNS domain"] in smb_domain_info["FQDN"] and
                '.' in smb_domain_info["FQDN"]):

            smb_domain_info["Derived domain"] = smb_domain_info["NetBIOS domain name"]
            smb_domain_info["Derived membership"] = "domain member"

            if not self.creds.local_auth:
                self.creds.set_domain(smb_domain_info["NetBIOS domain name"])
        elif (smb_domain_info["NetBIOS domain name"] and
                not smb_domain_info["NetBIOS computer name"] and
                not smb_domain_info["FQDN"] and
                not smb_domain_info["DNS domain"]):

            smb_domain_info["Derived domain"] = smb_domain_info["NetBIOS domain name"]
            smb_domain_info["Derived membership"] = "workgroup member"

            if not self.creds.local_auth:
                self.creds.set_domain(smb_domain_info["NetBIOS domain name"])
        elif smb_domain_info["NetBIOS computer name"]:

            smb_domain_info["Derived domain"] = "unknown"
            smb_domain_info["Derived membership"] = "workgroup member"

            if self.creds.local_auth:
                self.creds.set_domain(smb_domain_info["NetBIOS computer name"])

        # Fallback to default workgroup 'WORKGROUP' if nothing else can be found
        if not self.creds.domain:
            self.creds.set_domain('WORKGROUP')

        if not any(smb_domain_info.values()):
            return Result(None, "Could not enumerate domain information via unauthenticated SMB")
        return Result(smb_domain_info, f"Found domain information via SMB\n{yamlize(smb_domain_info)}")

### Domain Information Enumeration via lsaquery

class EnumLsaqueryDomainInfo():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module lsaquery which tries to get domain information like
        the domain/workgroup name, domain SID and the membership type.
        '''
        module_name = ENUM_LSAQUERY_DOMAIN_INFO
        print_heading(f"Domain Information via RPC for {self.target.host}")
        output = {}
        rpc_domain_info = {"Domain":None,
                           "Domain SID":None,
                           "Membership":None}

        lsaquery = self.lsaquery()
        if lsaquery.retval is not None:
            # Try to get domain/workgroup from lsaquery
            result = self.get_domain(lsaquery.retval)
            if result.retval:
                print_success(result.retmsg)
                rpc_domain_info["Domain"] = result.retval

                # In previous enumeration steps the domain was enumerated via unauthenticated
                # SMB session. The domain found there might not be correct. Therefore, we only inform
                # the user that we found a different domain via lsaquery. Jumping back to the session
                # checks does not make sense. If the user was able to call lsaquery, he is already
                # authenticated (likely via null session).
                if not self.creds.local_auth and not self.creds.set_domain(result.retval):
                    print_hint(f"Found domain/workgroup '{result.retval}' which is different from the currently used one '{self.creds.domain}'.")
            else:
                output = process_error(result.retmsg, ["rpc_domain_info"], module_name, output)

            # Try to get domain SID
            result = self.get_domain_sid(lsaquery.retval)
            if result.retval:
                print_success(result.retmsg)
                rpc_domain_info["Domain SID"] = result.retval
            else:
                output = process_error(result.retmsg, ["rpc_domain_info"], module_name, output)

            # Is the host part of a domain or a workgroup?
            result = self.check_is_part_of_workgroup_or_domain(lsaquery.retval)
            if result.retval:
                print_success(result.retmsg)
                rpc_domain_info["Membership"] = result.retval
            else:
                output = process_error(result.retmsg, ["rpc_domain_info"], module_name, output)
        else:
            output = process_error(lsaquery.retmsg, ["rpc_domain_info"], module_name, output)

        output["rpc_domain_info"] = rpc_domain_info
        return output

    def lsaquery(self):
        '''
        Uses the rpcclient command to connect to the named pipe LSARPC (Local Security Authority Remote Procedure Call),
        which allows to do remote management of domain security policies. In this specific case, we use rpcclient's lsaquery
        command. This command will do an LSA_QueryInfoPolicy request to get the domain name and the domain service identifier
        (SID).
        '''

        result = SambaRpcclient(['lsaquery'], self.target, self.creds).run(log='Attempting to get domain SID')

        if not result.retval:
            return Result(None, f"Could not get domain information via 'lsaquery': {result.retmsg}")

        if result.retval:
            return Result(result.retmsg, "")
        return Result(None, "Could not get information via 'lsaquery'")

    def get_domain(self, lsaquery_result):
        '''
        Takes the result of rpclient's lsaquery command and tries to extract the workgroup/domain.
        '''
        domain = ""
        if "Domain Name" in lsaquery_result:
            match = re.search("Domain Name: (.*)", lsaquery_result)
            if match:
                domain = match.group(1)

        if domain:
            return Result(domain, f"Domain: {domain}")
        return Result(None, "Could not get workgroup/domain from lsaquery")

    def get_domain_sid(self, lsaquery_result):
        '''
        Takes the result of rpclient's lsaquery command and tries to extract the domain SID.
        '''
        domain_sid = None
        if "Domain Sid: (NULL SID)" in lsaquery_result:
            domain_sid = "NULL SID"
        else:
            match = re.search(r"Domain Sid: (S-\d+-\d+-\d+-\d+-\d+-\d+)", lsaquery_result)
            if match:
                domain_sid = match.group(1)
        if domain_sid:
            return Result(domain_sid, f"Domain SID: {domain_sid}")
        return Result(None, "Could not get domain SID from lsaquery")

    def check_is_part_of_workgroup_or_domain(self, lsaquery_result):
        '''
        Takes the result of rpclient's lsaquery command and tries to determine from the result whether the host
        is part of a domain or workgroup.
        '''
        if "Domain Sid: S-0-0" in lsaquery_result or "Domain Sid: (NULL SID)" in lsaquery_result:
            return Result("workgroup member", "Membership: workgroup member")
        if re.search(r"Domain Sid: S-\d+-\d+-\d+-\d+-\d+-\d+", lsaquery_result):
            return Result("domain member", "Membership: domain member")
        return Result(False, "Could not determine if host is part of domain or part of a workgroup")

### OS Information Enumeration

class EnumOsInfo():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module OS info which tries to collect OS information. The module supports both authenticated and unauthenticated
        enumeration. This allows to get some target information without having a working session for many systems.
        '''
        module_name = ENUM_OS_INFO
        print_heading(f"OS Information via RPC for {self.target.host}")
        output = {"os_info":None}
        os_info = {"OS":None, "OS version":None, "OS release": None, "OS build": None, "Native OS":None, "Native LAN manager": None, "Platform id":None, "Server type":None, "Server type string":None}

        # Even an unauthenticated SMB session gives OS information about the target system, collect these first
        for port in self.target.smb_ports:
            self.target.port = port
            print_info(f"Enumerating via unauthenticated SMB session on {port}/tcp")
            result_smb = self.enum_from_smb()
            if result_smb.retval:
                print_success(result_smb.retmsg)
                break
            output = process_error(result_smb.retmsg, ["os_info"], module_name, output)

        if result_smb.retval:
            os_info = {**os_info, **result_smb.retval}

        # If the earlier checks for RPC users sessions succeeded, we can continue by enumerating info via rpcclient's srvinfo
        print_info("Enumerating via 'srvinfo'")
        if self.target.sessions[self.creds.auth_method]:
            result_srvinfo = self.enum_from_srvinfo()
            if result_srvinfo.retval:
                print_success(result_srvinfo.retmsg)
            else:
                output = process_error(result_srvinfo.retmsg, ["os_info"], module_name, output)

            if result_srvinfo.retval is not None:
                os_info = {**os_info, **result_srvinfo.retval}
        else:
            output = process_error("Skipping 'srvinfo' run, not possible with provided credentials", ["os_info"], module_name, output)

        # Take all collected information and generate os_info entry
        if result_smb.retval or (self.target.sessions[self.creds.auth_method] and result_srvinfo.retval):
            os_info = self.os_info_to_human(os_info)
            print_success(f"After merging OS information we have the following result:\n{yamlize(os_info)}")
            output["os_info"] = os_info

        return output

    def srvinfo(self):
        '''
        Uses rpcclient's srvinfo command to connect to the named pipe SRVSVC in order to call
        NetSrvGetInfo() on the target. This will return OS information (OS version, platform id,
        server type).
        '''

        result = SambaRpcclient(['srvinfo'], self.target, self.creds).run(log='Attempting to get OS info with command')

        if not result.retval:
            return Result(None, f"Could not get OS info via 'srvinfo': {result.retmsg}")

        # FIXME: Came across this when trying to have multiple RPC sessions open, should this be moved to NT_STATUS_COMMON_ERRORS?
        # This error is hard to reproduce.
        if "NT_STATUS_REQUEST_NOT_ACCEPTED" in result.retmsg:
            return Result(None, 'Could not get OS information via srvinfo: STATUS_REQUEST_NOT_ACCEPTED - too many RPC sessions open?')

        return Result(result.retmsg, "")

    def enum_from_srvinfo(self):
        '''
        Parses the output of rpcclient's srvinfo command and extracts the various information.
        '''
        result = self.srvinfo()

        if result.retval is None:
            return result

        os_info = {"OS version":None, "Server type":None, "Server type string":None, "Platform id":None}
        search_patterns = {
                "platform_id":"Platform id",
                "os version":"OS version",
                "server type":"Server type"
                }
        first = True
        for line in result.retval.splitlines():

            if first:
                match = re.search(r"\s+[^\s]+\s+(.*)", line)
                if match:
                    os_info['Server type string'] = match.group(1).rstrip()
                first = False

            for search_pattern in search_patterns.keys():
                match = re.search(fr"\s+{search_pattern}\s+:\s+(.*)", line)
                if match:
                    os_info[search_patterns[search_pattern]] = match.group(1)

        if not os_info:
            return Result(None, "Could not parse result of 'srvinfo' command, please open a GitHub issue")
        return Result(os_info, "Found OS information via 'srvinfo'")

    def enum_from_smb(self):
        '''
        Tries to set up an SMB null session. Even if the null session does not succeed, the SMB protocol will transfer
        some information about the remote system in the SMB "Session Setup Response" or the SMB "Session Setup andX Response"
        packet. This is the major and minor OS version as well as the build number. In SMBv1 also the "Native OS" as well as
        the "Native LAN Manager" will be reported.
        '''
        os_info = {"OS version":None, "OS release":None, "OS build":None, "Native LAN manager":None, "Native OS":None}

        os_major = None
        os_minor = None

        # For SMBv1 we can typically find the "Native OS" (e.g. "Windows 5.1")  and "Native LAN Manager"
        # (e.g. "Windows 2000 LAN Manager") field in the "Session Setup AndX Response" packet.
        # For SMBv2 and later we find the "OS Major" (e.g. 5), "OS Minor" (e.g. 1) as well as the
        # "OS Build" fields in the "SMB2 Session Setup Response packet".

        if self.target.smb1_supported:
            smb_conn = None
            try:
                smb_conn = SmbConnection(self.target, dialect=SMB_DIALECT)
                smb_conn.login()
            except Exception as e:
                error_msg = process_impacket_smb_exception(e, self.target)
                if not "STATUS_ACCESS_DENIED" in error_msg:
                    return Result(None, error_msg)

            if self.target.smb1_only:
                os_info["OS build"] = "not supported"
                os_info["OS release"] = "not supported"

            try:
                native_lanman = smb_conn.get_server_lanman()
                if native_lanman:
                    os_info["Native LAN manager"] = f"{native_lanman}"

                native_os = smb_conn.get_server_os()
                if native_os:
                    os_info["Native OS"] = f"{native_os}"
                    match = re.search(r"Windows ([0-9])\.([0-9])", native_os)
                    if match:
                        os_major = match.group(1)
                        os_minor = match.group(2)
            except AttributeError:
                os_info["Native LAN manager"] = "not supported"
                os_info["Native OS"] = "not supported"
            except:
                pass

        if not self.target.smb1_only:
            smb_conn = None
            try:
                smb_conn = SmbConnection(self.target, dialect=self.target.smb_preferred_dialect)
                smb_conn.login()
            except Exception as e:
                error_msg = process_impacket_smb_exception(e, self.target)
                if not "STATUS_ACCESS_DENIED" in error_msg:
                    return Result(None, error_msg)

            if not self.target.smb1_supported:
                os_info["Native LAN manager"] = "not supported"
                os_info["Native OS"] = "not supported"

            try:
                os_major = smb_conn.get_server_os_major()
                os_minor = smb_conn.get_server_os_minor()
            except:
                pass

            try:
                os_build = smb_conn.get_server_os_build()
                if os_build is not None:
                    os_info["OS build"] = f"{os_build}"
                    if str(os_build) in OS_RELEASE:
                        os_info["OS release"] = OS_RELEASE[f"{os_build}"]
                    else:
                        os_info["OS release"] = ""
                else:
                    os_info["OS build"] = "not supported"
                    os_info["OS release"] = "not supported"
            except:
                pass

        if os_major is not None and os_minor is not None:
            os_info["OS version"] = f"{os_major}.{os_minor}"
        else:
            os_info["OS version"] = "not supported"

        if not any(os_info.values()):
            return Result(None, "Could not enumerate information via unauthenticated SMB")
        return Result(os_info, "Found OS information via SMB")

    def os_info_to_human(self, os_info):
        native_lanman = os_info["Native LAN manager"]
        native_os = os_info["Native OS"]
        version = os_info["OS version"]
        server_type_string = os_info["Server type string"]
        os = "unknown"

        if native_lanman is not None and "Samba" in native_lanman:
            os = f"Linux/Unix ({native_lanman})"
        elif native_os is not None and "Windows" in native_os and not "Windows 5.0" in native_os:
            os = native_os
        elif server_type_string is not None and "Samba" in server_type_string:
            # Examples:
            # Wk Sv ... Samba 4.8.0-Debian
            # Wk Sv ... (Samba 3.0.0)
            match = re.search(r".*(Samba\s.*[^)])", server_type_string)
            if match:
                os = f"Linux/Unix ({match.group(1)})"
            else:
                os = "Linux/Unix"
        elif version in OS_VERSIONS:
            os = OS_VERSIONS[version]

        os_info["OS"] = os

        return os_info


### Users Enumeration via RPC

class EnumUsersRpc():
    def __init__(self, target, creds, detailed):
        self.target = target
        self.creds = creds
        self.detailed = detailed

    def run(self):
        '''
        Run module enum users.
        '''
        module_name = ENUM_USERS_RPC
        print_heading(f"Users via RPC on {self.target.host}")
        output = {}

        # Get user via querydispinfo
        print_info("Enumerating users via 'querydispinfo'")
        users_qdi = self.enum_from_querydispinfo()
        if users_qdi.retval is None:
            output = process_error(users_qdi.retmsg, ["users"], module_name, output)
            users_qdi_output = None
        else:
            print_success(users_qdi.retmsg)
            users_qdi_output = users_qdi.retval

        # Get user via enumdomusers
        print_info("Enumerating users via 'enumdomusers'")
        users_edu = self.enum_from_enumdomusers()
        if users_edu.retval is None:
            output = process_error(users_edu.retmsg, ["users"], module_name, output)
            users_edu_output = None
        else:
            print_success(users_edu.retmsg)
            users_edu_output = users_edu.retval

        # Merge both users dicts
        if users_qdi_output is not None and users_edu_output is not None:
            users = {**users_edu_output, **users_qdi_output}
        elif users_edu_output is None:
            users = users_qdi_output
        else:
            users = users_edu_output

        if users:
            if self.detailed:
                print_info("Enumerating users details")
                for rid in users.keys():
                    name = users[rid]['username']
                    user_details = self.get_details_from_rid(rid, name)
                    if user_details.retval:
                        print_success(user_details.retmsg)
                        users[rid]["details"] = user_details.retval
                    else:
                        output = process_error(user_details.retmsg, ["users"], module_name, output)
                        users[rid]["details"] = ""

            print_success(f"After merging user results we have {len(users.keys())} user(s) total:\n{yamlize(users, sort=True)}")

        output["users"] = users
        return output

    def querydispinfo(self):
        '''
        querydispinfo uses the Security Account Manager Remote Protocol (SAMR) named pipe to run the QueryDisplayInfo() request.
        This request will return users with their corresponding Relative ID (RID) as well as multiple account information like a
        description of the account.
        '''

        result = SambaRpcclient(['querydispinfo'], self.target, self.creds).run(log='Attempting to get userlist')

        if not result.retval:
            return Result(None, f"Could not find users via 'querydispinfo': {result.retmsg}")

        return Result(result.retmsg, "")

    def enumdomusers(self):
        '''
        enomdomusers command will again use the SAMR named pipe to run the EnumDomainUsers() request. This will again
        return a list of users with their corresponding RID (see querydispinfo()). This is possible since by default
        the registry key HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous = 0. If this is set to
        1 enumeration is no longer possible.
        '''

        result = SambaRpcclient(['enumdomusers'], self.target, self.creds).run(log='Attempting to get userlist')

        if not result.retval:
            return Result(None, f"Could not find users via 'enumdomusers': {result.retmsg}")

        return Result(result.retmsg, "")

    def enum_from_querydispinfo(self):
        '''
        Takes the result of rpclient's querydispinfo and tries to extract the users from it.
        '''
        users = {}
        querydispinfo = self.querydispinfo()

        if querydispinfo.retval is None:
            return querydispinfo

        # Example output of rpcclient's querydispinfo:
        # index: 0x2 RID: 0x3e9 acb: 0x00000010 Account: tester	Name: 	Desc:
        for line in filter(None, querydispinfo.retval.split('\n')):
            match = re.search(r"index:\s+.*\s+RID:\s+(0x[A-F-a-f0-9]+)\s+acb:\s+(.*)\s+Account:\s+(.*)\s+Name:\s+(.*)\s+Desc:\s+(.*)", line)
            if match:
                rid = match.group(1)
                rid = str(int(rid, 16))
                acb = match.group(2)
                username = match.group(3)
                name = match.group(4)
                description = match.group(5)
                users[rid] = OrderedDict({"username":username, "name":name, "acb":acb, "description":description})
            else:
                return Result(None, "Could not extract users from querydispinfo output, please open a GitHub issue")
        return Result(users, f"Found {len(users.keys())} user(s) via 'querydispinfo'")

    def enum_from_enumdomusers(self):
        '''
        Takes the result of rpclient's enumdomusers and tries to extract the users from it.
        '''
        users = {}
        enumdomusers = self.enumdomusers()

        if enumdomusers.retval is None:
            return enumdomusers

        # Example output of rpcclient's enumdomusers:
        # user:[tester] rid:[0x3e9]
        for line in enumdomusers.retval.splitlines():
            match = re.search(r"user:\[(.*)\]\srid:\[(0x[A-F-a-f0-9]+)\]", line)
            if match:
                username = match.group(1)
                rid = match.group(2)
                rid = str(int(rid, 16))
                users[rid] = {"username":username}
            else:
                return Result(None, "Could not extract users from eumdomusers output, please open a GitHub issue")
        return Result(users, f"Found {len(users.keys())} user(s) via 'enumdomusers'")

    def get_details_from_rid(self, rid, name):
        '''
        Takes an RID and makes use of the SAMR named pipe to call QueryUserInfo() on the given RID.
        The output contains lots of information about the corresponding user account.
        '''
        if not valid_rid(rid):
            return Result(None, f"Invalid rid passed: {rid}")

        details = OrderedDict()

        result = SambaRpcclient(['queryuser', f'{rid}'], self.target, self.creds).run(log='Attempting to get detailed user info')

        if not result.retval:
            return Result(None, f"Could not find details for user '{name}': {result.retmsg}")

        #FIXME: Examine - it is unclear why this is returned
        if "NT_STATUS_NO_SUCH_USER" in result.retmsg:
            return Result(None, f"Could not find details for user '{name}': STATUS_NO_SUCH_USER")

        match = re.search("([^\n]*User Name.*logon_hrs[^\n]*)", result.retmsg, re.DOTALL)
        if match:
            user_info = match.group(1)

            for line in filter(None, user_info.split('\n')):
                if re.match(r'^\t[A-Za-z][A-Za-z\s_\.0-9]*(:|\[[0-9\.]+\]\.\.\.)(\t|\s)?', line):
                    if ":" in line:
                        key, value = line.split(":", 1)
                    if "..." in line:
                        key, value = line.split("...", 1)

                    # Skip user and full name, we have this information already
                    if "User Name" in key or "Full Name" in key:
                        continue

                    key = key.strip()
                    value = value.strip()
                    details[key] = value
                else:
                    # If the regex above does not match, the output of the rpcclient queruser call must have
                    # changed. In this case, this would throw an exception since 'key' would be referenced before
                    # assignment. We catch that exception.
                    try:
                        if key not in details:
                            details[key] = line
                        else:
                            details[key] += "\n" + line
                    except:
                        return Result(None, f"Could not parse result of 'rpcclient' command, please open a GitHub issue")

            if "acb_info" in details and valid_hex(details["acb_info"]):
                for key in ACB_DICT:
                    if int(details["acb_info"], 16) & key:
                        details[ACB_DICT[key]] = True
                    else:
                        details[ACB_DICT[key]] = False

            return Result(details, f"Found details for user '{name}' (RID {rid})")
        return Result(None, f"Could not find details for user '{name}' (RID {rid})")

### Groups Enumeration via RPC

class EnumGroupsRpc():
    def __init__(self, target, creds, with_members, detailed):
        self.target = target
        self.creds = creds
        self.with_members = with_members
        self.detailed = detailed

    def run(self):
        '''
        Run module enum groups.
        '''
        module_name = ENUM_GROUPS_RPC
        print_heading(f"Groups via RPC on {self.target.host}")
        output = {}
        groups = None

        for grouptype in ["local", "builtin", "domain"]:
            print_info(f"Enumerating {grouptype} groups")
            enum = self.enum(grouptype)
            if enum.retval is None:
                output = process_error(enum.retmsg, ["groups"], module_name, output)
            else:
                if groups is None:
                    groups = {}
                print_success(enum.retmsg)
                groups.update(enum.retval)

        #FIXME: Adjust users enum stuff above so that it looks similar to this one?
        if groups:
            if self.with_members:
                print_info("Enumerating group members")
                for rid in groups.keys():
                    # Get group members
                    groupname = groups[rid]['groupname']
                    grouptype = groups[rid]['type']
                    group_members = self.get_members_from_name(groupname, grouptype, rid)
                    if group_members.retval or group_members.retval == '':
                        print_success(group_members.retmsg)
                    else:
                        output = process_error(group_members.retmsg, ["groups"], module_name, output)
                    groups[rid]["members"] = group_members.retval

            if self.detailed:
                print_info("Enumerating group details")
                for rid in groups.keys():
                    groupname = groups[rid]["groupname"]
                    grouptype = groups[rid]["type"]
                    details = self.get_details_from_rid(rid, groupname, grouptype)

                    if details.retval:
                        print_success(details.retmsg)
                    else:
                        output = process_error(details.retmsg, ["groups"], module_name, output)
                    groups[rid]["details"] = details.retval

            print_success(f"After merging groups results we have {len(groups.keys())} group(s) total:\n{yamlize(groups, sort=True)}")
        output["groups"] = groups
        return output

    def enum(self, grouptype):
        '''
        Tries to enumerate all groups by calling rpcclient's 'enumalsgroups builtin', 'enumalsgroups domain' as well
        as 'enumdomgroups'.
        '''
        grouptype_dict = {
            "builtin":['enumalsgroups', 'builtin'],
            "local":['enumalsgroups', 'domain'],
            "domain":['enumdomgroups']
        }

        if grouptype not in ["builtin", "domain", "local"]:
            return Result(None, f"Unsupported grouptype, supported types are: { ','.join(grouptype_dict.keys()) }")

        groups = {}
        enum = self.enum_by_grouptype(grouptype)

        if enum.retval is None:
            return enum

        if not enum.retval:
            return Result({}, f"Found 0 group(s) via '{' '.join(grouptype_dict[grouptype])}'")

        match = re.search("(group:.*)", enum.retval, re.DOTALL)
        if not match:
            return Result(None, f"Could not parse result of '{' '.join(grouptype_dict[grouptype])}' command, please open a GitHub issue")

        # Example output of rpcclient's group commands:
        # group:[RAS and IAS Servers] rid:[0x229]
        for line in enum.retval.splitlines():
            match = re.search(r"group:\[(.*)\]\srid:\[(0x[A-F-a-f0-9]+)\]", line)
            if match:
                groupname = match.group(1)
                rid = match.group(2)
                rid = str(int(rid, 16))
                groups[rid] = OrderedDict({"groupname":groupname, "type":grouptype})
            else:
                return Result(None, f"Could not extract groups from '{' '.join(grouptype_dict[grouptype])}' output, please open a GitHub issue")
        return Result(groups, f"Found {len(groups.keys())} group(s) via '{' '.join(grouptype_dict[grouptype])}'")

    def enum_by_grouptype(self, grouptype):
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
            return Result(None, f"Unsupported grouptype, supported types are: { ','.join(grouptype_dict.keys()) }")

        result = SambaRpcclient([grouptype_dict[grouptype]], self.target, self.creds).run(log=f'Attempting to get {grouptype} groups')

        if not result.retval:
            return Result(None, f"Could not get groups via '{grouptype_dict[grouptype]}': {result.retmsg}")

        return Result(result.retmsg, "")

    def get_members_from_name(self, groupname, grouptype, rid):
        '''
        Takes a group name as first argument and tries to enumerate the group members. This is don by using
        the 'net rpc group members' command.
        '''

        result = SambaNet(['rpc', 'group', 'members', groupname], self.target, self.creds).run(log=f"Attempting to get group memberships for {grouptype} group '{groupname}'")

        if not result.retval:
            return Result(None, f"Could not lookup members for {grouptype} group '{groupname}' (RID {rid}): {result.retmsg}")

        members_string = result.retmsg
        members = []
        for member in members_string.splitlines():
            if "Couldn't lookup SIDs" in member:
                return Result(None, f"Could not lookup members for {grouptype} group '{groupname}' (RID {rid}): insufficient user permissions, try a different user")
            if "Couldn't find group" in member:
                return Result(None, f"Could not lookup members for {grouptype} group '{groupname}' (RID {rid}): group not found")
            members.append(member)

        return Result(','.join(members), f"Found {len(members)} member(s) for {grouptype} group '{groupname}' (RID {rid})")

    def get_details_from_rid(self, rid, groupname, grouptype):
        '''
        Takes an RID and makes use of the SAMR named pipe to open the group with OpenGroup() on the given RID.
        '''
        if not valid_rid(rid):
            return Result(None, f"Invalid rid passed: {rid}")

        details = OrderedDict()

        result = SambaRpcclient(['querygroup', f'{rid}'], self.target, self.creds).run(log='Attempting to get detailed group info')

        if not result.retval:
            return Result(None, f"Could not find details for {grouptype} group '{groupname}': {result.retmsg}")

        #FIXME: Only works for domain groups, otherwise NT_STATUS_NO_SUCH_GROUP is returned
        if "NT_STATUS_NO_SUCH_GROUP" in result.retmsg:
            return Result(None, f"Could not get details for {grouptype} group '{groupname}' (RID {rid}): STATUS_NO_SUCH_GROUP")

        match = re.search("([^\n]*Group Name.*Num Members[^\n]*)", result.retmsg, re.DOTALL)
        if match:
            group_info = match.group(1)
            group_info = group_info.replace("\t", "")

            for line in filter(None, group_info.split('\n')):
                if ':' in line:
                    (key, value) = line.split(":", 1)
                    # Skip group name, we have this information already
                    if "Group Name" in key:
                        continue
                    details[key] = value
                else:
                    details[line] = ""

            return Result(details, f"Found details for {grouptype} group '{groupname}' (RID {rid})")
        return Result(None, f"Could not find details for {grouptype} group '{groupname}' (RID {rid})")

### RID Cycling

class RidCycleParams:
    '''
    Stores the various parameters needed for RID cycling. rid_ranges and known_usernames are mandatory.
    enumerated_input is a dictionary which contains already enumerated input like "users,
    "groups", "machines" and/or a domain sid. By default enumerated_input is an empty dict
    and will be filled up during the tool run.
    '''
    def __init__(self, rid_ranges, batch_size, known_usernames):
        self.rid_ranges = rid_ranges
        self.batch_size = batch_size
        self.known_usernames = known_usernames
        self.enumerated_input = {}

    def set_enumerated_input(self, enum_input):
        for key in ["users", "groups", "machines"]:
            if key in enum_input:
                self.enumerated_input[key] = enum_input[key]
            else:
                self.enumerated_input[key] = None

        if "rpc_domain_info" in enum_input and enum_input["rpc_domain_info"]["Domain SID"] and "NULL SID" not in enum_input["rpc_domain_info"]["Domain SID"]:
            self.enumerated_input["domain_sid"] = enum_input["rpc_domain_info"]["Domain SID"]
        else:
            self.enumerated_input["domain_sid"] = None

class RidCycling():
    def __init__(self, cycle_params, target, creds, detailed):
        self.cycle_params = cycle_params
        self.target = target
        self.creds = creds
        self.detailed = detailed

    def run(self):
        '''
        Run module RID cycling.
        '''
        module_name = RID_CYCLING
        print_heading(f"Users, Groups and Machines on {self.target.host} via RID Cycling")
        output = self.cycle_params.enumerated_input

        # Try to enumerate SIDs first, if we don't have the domain SID already
        if output["domain_sid"]:
            sids_list = [output["domain_sid"]]
        else:
            print_info("Trying to enumerate SIDs")
            sids = self.enum_sids(self.cycle_params.known_usernames)
            if sids.retval is None:
                output = process_error(sids.retmsg, ["users", "groups", "machines"], module_name, output)
                return output
            print_success(sids.retmsg)
            sids_list = sids.retval

        # Keep track of what we found...
        found_count = {"users": 0, "groups": 0, "machines": 0}

        # Run...
        for sid in sids_list:
            print_info(f"Trying SID {sid}")
            rid_cycler = self.rid_cycle(sid)
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
                if output[top_level_key] is not None and rid in output[top_level_key]:
                    continue

                print_success(result.retmsg)
                found_count[top_level_key] += 1

                # ...else we add the result at the right position.
                if output[top_level_key] is None:
                    output[top_level_key] = {}
                output[top_level_key][rid] = entry

                if self.detailed and ("users" in top_level_key or "groups" in top_level_key):
                    if "users" in top_level_key:
                        rid, entry = list(result.retval["users"].items())[0]
                        name = entry["username"]
                        details = EnumUsersRpc(self.target, self.creds, False).get_details_from_rid(rid, name)
                    elif "groups" in top_level_key:
                        rid, entry = list(result.retval["groups"].items())[0]
                        groupname = entry["groupname"]
                        grouptype = entry["type"]
                        details = EnumGroupsRpc(self.target, self.creds, False, False).get_details_from_rid(rid, groupname, grouptype)

                    if details.retval:
                        print_success(details.retmsg)
                    else:
                        output = process_error(details.retmsg, [top_level_key], module_name, output)
                    output[top_level_key][rid]["details"] = details.retval

        if found_count["users"] == 0 and found_count["groups"] == 0 and found_count["machines"] == 0:
            output = process_error("Could not find any (new) users, (new) groups or (new) machines", ["users", "groups", "machines"], module_name, output)
        else:
            print_success(f"Found {found_count['users']} user(s), {found_count['groups']} group(s), {found_count['machines']} machine(s) in total")

        return output

    def enum_sids(self, users):
        '''
        Tries to enumerate SIDs by looking up user names via rpcclient's lookupnames and by using rpcclient's lsaneumsid.
        '''
        sids = []
        sid_patterns_list = [r"(S-1-5-21-[\d-]+)-\d+", r"(S-1-5-[\d-]+)-\d+", r"(S-1-22-[\d-]+)-\d+"]

        # Try to get a valid SID from well-known user names
        for known_username in users.split(','):
            result = SambaRpcclient(['lookupnames', f'{known_username}'], self.target, self.creds).run(log=f'Attempting to get SID for user {known_username}', error_filter=False)
            sid_string = result.retmsg

            #FIXME: Should we use nt_status_error_filter here? (mind error_filter above)
            if "NT_STATUS_ACCESS_DENIED" in sid_string or "NT_STATUS_NONE_MAPPED" in sid_string:
                continue

            for pattern in sid_patterns_list:
                match = re.search(pattern, sid_string)
                if match:
                    result = match.group(1)
                    if result not in sids:
                        sids.append(result)

        # Try to get SID list via lsaenumsid
        result = SambaRpcclient(['lsaenumsid'], self.target, self.creds).run(log="Attempting to get SIDs via 'lsaenumsid'", error_filter=False)

        #FIXME: Should we use nt_status_error_filter here? (mind error_filter above)
        if "NT_STATUS_ACCESS_DENIED" not in result.retmsg:
            for pattern in sid_patterns_list:
                match_list = re.findall(pattern, result.retmsg)
                for match in match_list:
                    if match not in sids:
                        sids.append(match)

        if sids:
            return Result(sids, f"Found {len(sids)} SID(s)")
        return Result(None, "Could not get any SIDs")

    def rid_cycle(self, sid):
        '''
        Takes a SID as first parameter well as list of RID ranges (as tuples) as second parameter and does RID cycling.
        '''
        for rid_range in self.cycle_params.rid_ranges:
            (start_rid, end_rid) = rid_range

            for rid_base in range(start_rid, end_rid+1, self.cycle_params.batch_size):
                target_sids = " ".join(list(map(lambda x: f'{sid}-{x}', range(rid_base, min(end_rid+1, rid_base+self.cycle_params.batch_size)))))
                #FIXME: Could we get rid of error_filter=False?
                result = SambaRpcclient(['lookupsids', target_sids], self.target, self.creds).run(log='RID Cycling', error_filter=False)

                for rid_offset, line in enumerate(result.retmsg.splitlines()):
                    # Example: S-1-5-80-3139157870-2983391045-3678747466-658725712-1004 *unknown*\*unknown* (8)
                    match = re.search(r"(S-\d+-\d+-\d+-[\d-]+\s+(.*)\s+[^\)]+\))", line)
                    if match:
                        sid_and_user = match.group(1)
                        entry = match.group(2)
                        rid = rid_base + rid_offset

                        # Samba servers sometimes claim to have user accounts
                        # with the same name as the UID/RID. We don't report these.
                        if re.search(r"-(\d+) .*\\\1 \(", sid_and_user):
                            continue

                        # "(1)" = User, "(2)" = Domain Group,"(3)" = Domain SID,"(4)" = Local Group
                        # "(5)" = Well-known group, "(6)" = Deleted account, "(7)" = Invalid account
                        # "(8)" = Unknown, "(9)" = Machine/Computer account
                        if "(1)" in sid_and_user:
                            yield Result({"users":{str(rid):{"username":entry}}}, f"Found user '{entry}' (RID {rid})")
                        elif "(2)" in sid_and_user:
                            yield Result({"groups":{str(rid):{"groupname":entry, "type":"domain"}}}, f"Found domain group '{entry}' (RID {rid})")
                        elif "(3)" in sid_and_user:
                            yield Result({"domain_sid":f"{sid}-{rid}"}, f"Found domain SID {sid}-{rid}")
                        elif "(4)" in sid_and_user:
                            yield Result({"groups":{str(rid):{"groupname":entry, "type":"builtin"}}}, f"Found builtin group '{entry}' (RID {rid})")
                        elif "(9)" in sid_and_user:
                            yield Result({"machines":{str(rid):{"machine":entry}}}, f"Found machine '{entry}' (RID {rid})")

### Shares Enumeration

class EnumShares():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module enum shares.
        '''
        module_name = ENUM_SHARES
        print_heading(f"Shares via RPC on {self.target.host}")
        output = {}
        shares = None

        enum = self.enum()
        if enum.retval is None:
            output = process_error(enum.retmsg, ["shares"], module_name, output)
        else:
            print_info("Enumerating shares")
            # This will print success even if no shares were found (which is not an error.)
            print_success(enum.retmsg)
            shares = enum.retval
            # Check access if there are any shares.
            if enum.retmsg:
                for share in sorted(shares):
                    print_info(f"Testing share {share}")
                    access = self.check_access(share)
                    if access.retval is None:
                        output = process_error(access.retmsg, ["shares"], module_name, output)
                        continue
                    print_success(access.retmsg)
                    shares[share]['access'] = access.retval

        output["shares"] = shares
        return output

    def enum(self):
        '''
        Tries to enumerate shares with the given username and password. It does this running the smbclient command.
        smbclient will open a connection to the Server Service Remote Protocol named pipe (srvsvc). Once connected
        it calls the NetShareEnumAll() to get a list of shares.
        '''

        result = SambaSmbclient(['list'], self.target, self.creds).run(log='Attempting to get share list using authentication')

        if not result.retval:
            return Result(None, f"Could not list shares: {result.retmsg}")

        shares = {}
        match_list = re.findall(r"^(Device|Disk|IPC|Printer)\|(.*)\|(.*)$", result.retmsg, re.MULTILINE|re.IGNORECASE)
        if match_list:
            for entry in match_list:
                share_type = entry[0]
                share_name = entry[1]
                share_comment = entry[2].rstrip()
                shares[share_name] = {'type':share_type, 'comment':share_comment}

        if shares:
            return Result(shares, f"Found {len(shares.keys())} share(s):\n{yamlize(shares, sort=True)}")
        return Result(shares, f"Found 0 share(s) for user '{self.creds.user}' with password '{self.creds.pw}', try a different user")

    def check_access(self, share):
        '''
        Takes a share as first argument and checks whether the share is accessible.
        The function returns a dictionary with the keys "mapping" and "listing".
        "mapping" can be either OK or DENIED. OK means the share exists and is accessible.
        "listing" can bei either OK, DENIED, N/A, NOT SUPPORTED or WRONG PASSWORD.
        N/A means directory listing is not allowed, while NOT SUPPORTED means the share does
        not support listing at all. This is the case for shares like IPC$ which is used for
        remote procedure calls.

        In order to enumerate access permissions, smbclient is used with the "dir" command.
        In the background this will send an SMB I/O Control (IOCTL) request in order to list the contents of the share.
        '''

        result = SambaSmbclient(['dir', f'{share}'], self.target, self.creds).run(log=f'Attempting to map share //{self.target.host}/{share}', error_filter=False)

        if "NT_STATUS_BAD_NETWORK_NAME" in result.retmsg:
            return Result(None, "Share doesn't exist")

        if "NT_STATUS_ACCESS_DENIED listing" in result.retmsg:
            return Result({"mapping":"ok", "listing":"denied"}, "Mapping: OK, Listing: DENIED")

        if "NT_STATUS_WRONG_PASSWORD" in result.retmsg:
            return Result({"mapping":"ok", "listing":"wrong password"}, "Mapping: OK, Listing: WRONG PASSWORD")

        if "tree connect failed: NT_STATUS_ACCESS_DENIED" in result.retmsg:
            return Result({"mapping":"denied", "listing":"n/a"}, "Mapping: DENIED, Listing: N/A")

        if "NT_STATUS_INVALID_INFO_CLASS" in result.retmsg\
                or "NT_STATUS_CONNECTION_REFUSED listing" in result.retmsg\
                or "NT_STATUS_NETWORK_ACCESS_DENIED" in result.retmsg\
                or "NT_STATUS_NOT_A_DIRECTORY" in result.retmsg\
                or "NT_STATUS_NO_SUCH_FILE" in result.retmsg:
            return Result({"mapping":"ok", "listing":"not supported"}, "Mapping: OK, Listing: NOT SUPPORTED")

        if "NT_STATUS_OBJECT_NAME_NOT_FOUND" in result.retmsg:
            return Result(None, "Could not check share: STATUS_OBJECT_NAME_NOT_FOUND")

        if "NT_STATUS_INVALID_PARAMETER" in result.retmsg:
            return Result(None, "Could not check share: STATUS_INVALID_PARAMETER")

        if re.search(r"\n\s+\.\.\s+D.*\d{4}\n", result.retmsg) or re.search(r".*blocks\sof\ssize.*blocks\savailable.*", result.retmsg):
            return Result({"mapping":"ok", "listing":"ok"}, "Mapping: OK, Listing: OK")

        return Result(None, "Could not parse result of smbclient command, please open a GitHub issue")

### Share Brute-Force

class ShareBruteParams:
    '''
    Stores the various parameters needed for Share Bruteforcing. shares_file is mandatory.
    enumerated_input is a dictionary which contains already enumerated shares. By default
    enumerated_input is an empty dict and will be filled up during the tool run.
    '''
    def __init__(self, shares_file):
        self.shares_file = shares_file
        self.enumerated_input = {}

    def set_enumerated_input(self, enum_input):
        if "shares" in enum_input:
            self.enumerated_input["shares"] = enum_input["shares"]
        else:
            self.enumerated_input["shares"] = None

class BruteForceShares():
    def __init__(self, brute_params, target, creds):
        self.brute_params = brute_params
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module bruteforce shares.
        '''
        module_name = BRUTE_FORCE_SHARES
        print_heading(f"Share Bruteforcing on {self.target.host}")
        output = self.brute_params.enumerated_input

        found_count = 0
        try:
            with open(self.brute_params.shares_file) as f:
                for share in f:
                    share = share.rstrip()

                    # Skip all shares we might have found by the enum_shares module already
                    if output["shares"] is not None and share in output["shares"].keys():
                        continue

                    result = EnumShares(self.target, self.creds).check_access(share)
                    if result.retval:
                        if output["shares"] is None:
                            output["shares"] = {}
                        print_success(f"Found share: {share}")
                        print_success(result.retmsg)
                        output["shares"][share] = result.retval
                        found_count += 1
        except:
            output = process_error(f"Failed to open {self.brute_params.shares_file}", ["shares"], module_name, output)

        if found_count == 0:
            output = process_error("Could not find any (new) shares", ["shares"], module_name, output)
        else:
            print_success(f"Found {found_count} (new) share(s) in total")

        return output

### Policy Enumeration

class EnumPolicy():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module enum policy.
        '''
        module_name = ENUM_POLICY
        print_heading(f"Policies via RPC for {self.target.host}")
        output = {}

        for port in self.target.smb_ports:
            print_info(f"Trying port {port}/tcp")
            self.target.port = port
            enum = self.enum()
            if enum.retval is None:
                output = process_error(enum.retmsg, ["policy"], module_name, output)
                output["policy"] = None
            else:
                print_success(enum.retmsg)
                output["policy"] = enum.retval
                break

        return output

    # This function is heavily based on this polenum fork: https://github.com/Wh1t3Fox/polenum
    # The original polenum was written by Richard "deanx" Dean: https://labs.portcullis.co.uk/tools/polenum/
    # All credits to Richard "deanx" Dean and Craig "Wh1t3Fox" West!
    def enum(self):
        '''
        Tries to enum password policy and domain lockout and logoff information by opening a connection to the SAMR
        named pipe and calling SamQueryInformationDomain() as well as SamQueryInformationDomain2().
        '''
        policy = {}

        try:
            smb_conn = SmbConnection(self.target, self.creds)
            smb_conn.login()
            samr_object = SAMR(smb_conn)
            domains = samr_object.get_domains()
            # FIXME: Gets policy for domain only, [1] stores the policy for BUILTIN
            domain_handle = samr_object.get_domain_handle(domains[0])
        except Exception as e:
            return Result(None, process_impacket_smb_exception(e, self.target))

        try:
            result = samr_object.get_domain_password_information(domain_handle)

            policy["Domain password information"] = {}
            policy["Domain password information"]["Password history length"] = result['PasswordHistoryLength'] or "None"
            policy["Domain password information"]["Minimum password length"] = result['MinPasswordLength'] or "None"
            policy["Domain password information"]["Maximum password age"] = self.policy_to_human(int(result['MinPasswordAge']['LowPart']), int(result['MinPasswordAge']['HighPart']))
            policy["Domain password information"]["Maximum password age"] = self.policy_to_human(int(result['MaxPasswordAge']['LowPart']), int(result['MaxPasswordAge']['HighPart']))
            policy["Domain password information"]["Password properties"] = []
            pw_prop = result['PasswordProperties']
            for bitmask in DOMAIN_FIELDS:
                if pw_prop & bitmask == bitmask:
                    policy["Domain password information"]["Password properties"].append({DOMAIN_FIELDS[bitmask]:True})
                else:
                    policy["Domain password information"]["Password properties"].append({DOMAIN_FIELDS[bitmask]:False})
        except Exception as e:
            nt_status_error = nt_status_error_filter(str(e))
            if nt_status_error:
                return Result(None, f"Could not get domain password policy: {nt_status_error}")
            return Result(None, "Could not get domain password policy")

        # Domain lockout
        try:
            result = samr_object.get_domain_lockout_information(domain_handle)

            policy["Domain lockout information"] = {}
            policy["Domain lockout information"]["Lockout observation window"] = self.policy_to_human(0, result['LockoutObservationWindow'], lockout=True)
            policy["Domain lockout information"]["Lockout duration"] = self.policy_to_human(0, result['LockoutDuration'], lockout=True)
            policy["Domain lockout information"]["Lockout threshold"] = result['LockoutThreshold'] or "None"
        except Exception as e:
            nt_status_error = nt_status_error_filter(str(e))
            if nt_status_error:
                return Result(None, f"Could not get domain lockout policy: {nt_status_error}")
            return Result(None, "Could not get domain lockout policy")

        # Domain logoff
        try:
            result = samr_object.get_domain_logoff_information(domain_handle)

            policy["Domain logoff information"] = {}
            policy["Domain logoff information"]["Force logoff time"] = self.policy_to_human(result['ForceLogoff']['LowPart'], result['ForceLogoff']['HighPart'])
        except Exception as e:
            nt_status_error = nt_status_error_filter(str(e))
            if nt_status_error:
                return Result(None, f"Could not get domain logoff policy: {nt_status_error}")
            return Result(None, "Could not get domain logoff policy")

        return Result(policy, f"Found policy:\n{yamlize(policy)}")

    # This function is heavily based on this polenum fork: https://github.com/Wh1t3Fox/polenum
    # The original polenum was written by Richard "deanx" Dean: https://labs.portcullis.co.uk/tools/polenum/
    # All credits to Richard "deanx" Dean and Craig "Wh1t3Fox" West!
    def policy_to_human(self, low, high, lockout=False):
        '''
        Converts various values retrieved via the SAMR named pipe into human readable strings.
        '''
        time = ""
        tmp = 0

        if low == 0 and hex(high) == "-0x80000000":
            return "not set"
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
            minutes = datetime.utcfromtimestamp(tmp).minute
            hours = datetime.utcfromtimestamp(tmp).hour
            time_diff = datetime.utcfromtimestamp(tmp) - datetime.utcfromtimestamp(0)
            days = time_diff.days
        except:
            return "invalid time"

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

### Printer Enumeration

class EnumPrinters():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module enum printers.
        '''
        module_name = ENUM_PRINTERS
        print_heading(f"Printers via RPC for {self.target.host}")
        output = {}

        enum = self.enum()
        if enum.retval is None:
            output = process_error(enum.retmsg, ["printers"], module_name, output)
            output["printers"] = None
        else:
            print_success(enum.retmsg)
            output["printers"] = enum.retval
        return output

    def enum(self):
        '''
        Tries to enum printer via rpcclient's enumprinters.
        '''

        result = SambaRpcclient(['enumprinters'], self.target, self.creds).run(log='Attempting to get printer info')
        printers = {}

        if not result.retval:
            return Result(None, f"Could not get printer info via 'enumprinters': {result.retmsg}")

        #FIXME: Not 100% about this one, is the spooler propably not running?
        if "NT_STATUS_OBJECT_NAME_NOT_FOUND" in result.retmsg:
            return Result("", "No printers available")
        if "No printers returned." in result.retmsg:
            return Result({}, "No printers returned (this is not an error)")

        nt_status_error = nt_status_error_filter(result.retmsg)
        if nt_status_error:
            return Result(None, f"Could not get printers via 'enumprinters': {nt_status_error}")
        #FIXME: It seems as this error has disappered in newer versions?
        if "WERR_INVALID_NAME" in result.retmsg:
            return Result(None, "Could not get printers via 'enumprinters': WERR_INVALID_NAME")

        match_list = re.findall(r"\s*flags:\[([^\n]*)\]\n\s*name:\[([^\n]*)\]\n\s*description:\[([^\n]*)\]\n\s*comment:\[([^\n]*)\]", result.retmsg, re.MULTILINE)
        if not match_list:
            return Result(None, "Could not parse result of enumprinters command, please open a GitHub issue")

        for match in match_list:
            flags = match[0]
            name = match[1]
            description = match[2]
            comment = match[3]
            printers[name] = OrderedDict({"description":description, "comment":comment, "flags":flags})

        return Result(printers, f"Found {len(printers.keys())} printer(s):\n{yamlize(printers, sort=True)}")

### Services Enumeration

class EnumServices():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module enum services.
        '''
        module_name = ENUM_SERVICES
        print_heading(f"Services via RPC on {self.target.host}")
        output = {'services':None}

        enum = self.enum()
        if enum.retval is None:
            output = process_error(enum.retmsg, ["services"], module_name, output)
        else:
            print_success(enum.retmsg)
            output['services'] = enum.retval

        return output

    def enum(self):
        '''
        Tries to enum RPC services via net rpc service list.
        '''

        result = SambaNet(['rpc', 'service', 'list'], self.target, self.creds).run(log='Attempting to get RPC services')
        services = {}

        if not result.retval:
            return Result(None, f"Could not get RPC services via 'net rpc service list': {result.retmsg}")

        match_list = re.findall(r"([^\s]*)\s*\"(.*)\"", result.retmsg, re.MULTILINE)
        if not match_list:
            return Result(None, "Could not parse result of 'net rpc service list' command, please open a GitHub issue")

        for match in match_list:
            name = match[0]
            description = match[1]
            services[name] = OrderedDict({"description":description})

        return Result(services, f"Found {len(services.keys())} service(s):\n{yamlize(services, True)}")

### Enumerator

class Enumerator():
    def __init__(self, args):

        # Init output files
        if args.out_json_file:
            output = Output(args.out_json_file, "json")
        elif args.out_yaml_file:
            output = Output(args.out_yaml_file, "yaml")
        elif args.out_file:
            output = Output(args.out_file, "json_yaml")
        else:
            output = Output()

        # Init target and creds
        try:
            self.creds = Credentials(args.user, args.pw, args.domain, args.ticket_file, args.nthash, args.local_auth)
            self.target = Target(args.host, self.creds, timeout=args.timeout)
        except Exception as e:
            raise RuntimeError(str(e))

        # Init default SambaConfig, make sure 'client ipc signing' is not required
        try:
            samba_config = SambaConfig(['client ipc signing = auto'])
            self.target.samba_config = samba_config
        except:
            raise RuntimeError("Could not create default samba configuration")

        # Add target host and creds to output, so that it will end up in the JSON/YAML
        output.update(self.target.as_dict())
        output.update(self.creds.as_dict())

        self.args = args
        self.output = output
        self.cycle_params = None
        self.share_brute_params = None

    def run(self):
        # RID Cycling - init parameters
        if self.args.R:
            rid_ranges = self.prepare_rid_ranges()
            self.cycle_params = RidCycleParams(rid_ranges, self.args.R, self.args.users)

        # Shares Brute Force - init parameters
        if self.args.shares_file:
            self.share_brute_params = ShareBruteParams(self.args.shares_file)

        print_heading("Target Information", False)
        print_info(f"Target ........... {self.target.host}")
        print_info(f"Username ......... '{self.creds.user}'")
        print_info(f"Random Username .. '{self.creds.random_user}'")
        print_info(f"Password ......... '{self.creds.pw}'")
        print_info(f"Timeout .......... {self.target.timeout} second(s)")
        if self.args.R:
            print_info(f"RID Range(s) ..... {self.args.ranges}")
            print_info(f"RID Req Size ..... {self.args.R}")
            print_info(f"Known Usernames .. '{self.args.users}'")

        # The enumeration starts with a service scan. Currently this scans for
        # SMB and LDAP, simple TCP connect scan is used for that. From the result
        # of the scan and the arguments passed in by the user, a list of modules
        # is generated. These modules will then be run.
        listeners = self.service_scan()
        self.target.listeners = listeners
        modules = self.get_modules(listeners)
        self.run_modules(modules)

    def service_scan(self):
        # By default we scan for 445/tcp and 139/tcp (SMB).
        # LDAP will be added if the user requested any option which requires LDAP
        # like -L or -A.
        scan_list = [SERVICE_SMB, SERVICE_SMB_NETBIOS]
        if self.args.L:
            scan_list += [SERVICE_LDAP, SERVICE_LDAPS]

        scanner = ListenersScan(self.target, scan_list)
        result = scanner.run()
        self.output.update(result)
        self.target.smb_ports = scanner.get_accessible_ports_by_pattern("SMB")
        self.target.ldap_ports = scanner.get_accessible_ports_by_pattern("LDAP")
        return scanner.get_accessible_listeners()

    def get_modules(self, listeners, session=True):
        modules = []
        if self.args.N:
            modules.append(ENUM_NETBIOS)

        if SERVICE_LDAP in listeners or SERVICE_LDAPS in listeners:
            if self.args.L:
                modules.append(ENUM_LDAP_DOMAIN_INFO)

        if SERVICE_SMB in listeners or SERVICE_SMB_NETBIOS in listeners:
            modules.append(ENUM_SMB)
            modules.append(ENUM_SMB_DOMAIN_INFO)
            modules.append(ENUM_SESSIONS)

            # The OS info module supports both session-less (unauthenticated) and session-based (authenticated)
            # enumeration. Therefore, we can run it even if no session was possible...
            if self.args.O:
                modules.append(ENUM_OS_INFO)

            # ...the remaining modules still need a working session.
            if session:
                modules.append(ENUM_LSAQUERY_DOMAIN_INFO)
                if self.args.U:
                    modules.append(ENUM_USERS_RPC)
                if self.args.G:
                    modules.append(ENUM_GROUPS_RPC)
                if self.args.Gm:
                    modules.append(ENUM_GROUPS_RPC)
                if self.args.R:
                    modules.append(RID_CYCLING)
                if self.args.S:
                    modules.append(ENUM_SHARES)
                if self.args.shares_file:
                    modules.append(BRUTE_FORCE_SHARES)
                if self.args.P:
                    modules.append(ENUM_POLICY)
                if self.args.I:
                    modules.append(ENUM_PRINTERS)
                if self.args.C:
                    modules.append(ENUM_SERVICES)

        return modules

    def run_modules(self, modules):
        # Checks if host is a parent/child domain controller, try to get long domain name
        if ENUM_LDAP_DOMAIN_INFO in modules:
            result = EnumLdapDomainInfo(self.target).run()
            self.output.update(result)

        # Try to retrieve workstation/domain and nbtstat information
        if ENUM_NETBIOS in modules:
            result = EnumNetbios(self.target, self.creds).run()
            self.output.update(result)

        # Enumerate supported SMB versions
        if ENUM_SMB in modules:
            result = EnumSmb(self.target, self.args.d).run()
            self.output.update(result)

        # Try to get domain name and sid via lsaquery
        if ENUM_SMB_DOMAIN_INFO in modules:
            result = EnumSmbDomainInfo(self.target, self.creds).run()
            self.output.update(result)

        # Check for various session types including null sessions
        if ENUM_SESSIONS in modules:
            result = EnumSessions(self.target, self.creds).run()
            self.output.update(result)
            self.target.sessions = self.output.as_dict()['sessions']

        # If sessions are not possible, we regenerate the list of modules again.
        # This will only leave those modules in, which don't require authentication.
        if self.target.sessions and not self.target.sessions[self.creds.auth_method]:
            modules = self.get_modules(self.target.listeners, session=False)

        # Try to get domain name and sid via lsaquery
        if ENUM_LSAQUERY_DOMAIN_INFO in modules:
            result = EnumLsaqueryDomainInfo(self.target, self.creds).run()
            self.output.update(result)

        # Get OS information like os version, server type string...
        if ENUM_OS_INFO in modules:
            result = EnumOsInfo(self.target, self.creds).run()
            self.output.update(result)

        # Enum users
        if ENUM_USERS_RPC in modules:
            result = EnumUsersRpc(self.target, self.creds, self.args.d).run()
            self.output.update(result)

        # Enum groups
        if ENUM_GROUPS_RPC in modules:
            result = EnumGroupsRpc(self.target, self.creds, self.args.Gm, self.args.d).run()
            self.output.update(result)

        # Enum RPC services
        if ENUM_SERVICES in modules:
            result = EnumServices(self.target, self.creds).run()
            self.output.update(result)

        # Enum shares
        if ENUM_SHARES in modules:
            result = EnumShares(self.target, self.creds).run()
            self.output.update(result)

        # Enum password policy
        if ENUM_POLICY in modules:
            result = EnumPolicy(self.target, self.creds).run()
            self.output.update(result)

        # Enum printers
        if ENUM_PRINTERS in modules:
            result = EnumPrinters(self.target, self.creds).run()
            self.output.update(result)

        # RID Cycling (= bruteforce users, groups and machines)
        if RID_CYCLING in modules:
            self.cycle_params.set_enumerated_input(self.output.as_dict())
            result = RidCycling(self.cycle_params, self.target, self.creds, self.args.d).run()
            self.output.update(result)

        # Brute force shares
        if BRUTE_FORCE_SHARES in modules:
            self.share_brute_params.set_enumerated_input(self.output.as_dict())
            result = BruteForceShares(self.share_brute_params, self.target, self.creds).run()
            self.output.update(result)

        if not self.target.listeners:
            warn("Aborting remainder of tests since neither SMB nor LDAP are accessible")
        elif self.target.sessions['sessions_possible'] and not self.target.sessions[self.creds.auth_method]:
            warn("Aborting remainder of tests, sessions are possible, but not with the provided credentials (see session check results)")
        elif not self.target.sessions['sessions_possible']:
            if SERVICE_SMB not in self.target.listeners and SERVICE_SMB_NETBIOS not in self.target.listeners:
                warn("Aborting remainder of tests since SMB is not accessible")
            else:
                warn("Aborting remainder of tests since sessions failed, rerun with valid credentials")

    def prepare_rid_ranges(self):
        '''
        Takes a string containing muliple RID ranges and returns a list of ranges as tuples.
        '''
        rid_ranges = self.args.ranges
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

    def finish(self):
        errors = []

        # Delete temporary samba config
        if hasattr(self, 'target'):
            if self.target.samba_config is not None and not self.args.keep:
                result = self.target.samba_config.delete()
                if not result.retval:
                    errors.append(result.retmsg)

        # Write YAML/JSON output (if the user requested that)
        if hasattr(self, 'output'):
            result = self.output.flush()
            if not result.retval:
                errors.append(result.retmsg)

        if errors:
            return Result(False, "\n".join(errors))
        return Result(True, "")

### Validation Functions

def valid_value(value, bounds):
    min_val, max_val = bounds
    try:
        value = int(value)
        if min_val <= value <= max_val:
            return True
    except ValueError:
        pass
    return False

def valid_rid_ranges(rid_ranges):
    if not rid_ranges:
        return False

    for rid_range in rid_ranges.split(','):
        match = re.search(r"^(\d+)-(\d+)$", rid_range)
        if match:
            continue
        if rid_range.isdigit():
            continue
        return False
    return True

def valid_shares_file(shares_file):
    fault_shares = []
    NL = '\n'

    result = valid_file(shares_file)
    if not result.retval:
        return result

    try:
        with open(shares_file) as f:
            line_num = 1
            for share in f:
                share = share.rstrip()
                if not valid_share(share):
                    fault_shares.append(f"line {line_num}:{share}")
                line_num += 1
    except:
        return Result(False, f"Could not open shares file {shares_file}")
    if fault_shares:
        return Result(False, f"Shares with illegal characters found in {shares_file}:\n{NL.join(fault_shares)}")
    return Result(True, "")

def valid_share(share):
    if re.search(r"^[a-zA-Z0-9\._\$-]+$", share):
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

def valid_domain(domain):
    if re.match(r"^[A-Za-z0-9_\.-]+$", domain):
        return True
    return False

def valid_file(file, mode=os.R_OK):
    if not os.path.exists(file):
        return Result(False, f'File {file} does not exist')

    if os.stat(file).st_size == 0:
        return Result(False, f'File {file} is empty')

    if not os.access(file, mode):
        if mode == os.R_OK:
            return Result(False, f'Cannot read file {file}')
        if mode == os.W_OK:
            return Result(False, f'Cannot write file {file}')

    return Result(True, '')

### Print Functions and Error Processing

def print_banner():
    print(f"{Colors.green(f'ENUM4LINUX - next generation (v{GLOBAL_VERSION})')}\n")

def print_heading(text, leading_newline=True):
    output = f"|    {text}    |"
    length = len(output)

    if leading_newline:
        print()
    print(" " + "="*(length-2))
    print(output)
    print(" " + "="*(length-2))

def print_success(msg):
    print(Colors.green(f"[+] {msg}"))

def print_hint(msg):
    print(Colors.green(f"[H] {msg}"))

def print_error(msg):
    print(Colors.red(f"[-] {msg}"))

def print_info(msg):
    print(Colors.blue(f"[*] {msg}"))

def print_verbose(msg):
    print(f"[V] {msg}")

def process_error(msg, affected_entries, module_name, output_dict):
    '''
    Helper function to print error and update output dictionary at the same time.
    '''
    print_error(msg)

    if not "errors" in output_dict:
        output_dict["errors"] = {}

    for entry in affected_entries:
        if not entry in output_dict["errors"]:
            output_dict["errors"].update({entry: {}})

        if not module_name in output_dict["errors"][entry]:
            output_dict["errors"][entry].update({module_name: []})

        output_dict["errors"][entry][module_name].append(msg)
    return output_dict

def process_impacket_smb_exception(exception, target):
    '''
    Function for handling exceptions during SMB session setup when using the impacket library.
    '''
    if len(exception.args) == 2:
        if isinstance(exception.args[1], ConnectionRefusedError):
            return f"SMB connection error on port {target.port}/tcp: Connection refused"
        if isinstance(exception.args[1], socket.timeout):
            return f"SMB connection error on port {target.port}/tcp: timed out"
    if isinstance(exception, nmb.NetBIOSError):
        return f"SMB connection error on port {target.port}/tcp: session failed"
    if isinstance(exception, (smb.SessionError, smb3.SessionError)):
        nt_status_error = nt_status_error_filter(str(exception))
        if nt_status_error:
            return f"SMB connection error on port {target.port}/tcp: {nt_status_error}"
        return f"SMB connection error on port {target.port}/tcp: session failed"
    if isinstance(exception, AttributeError):
        return f"SMB connection error on port {target.port}/tcp: session failed"
    nt_status_error = nt_status_error_filter(str(exception))
    if nt_status_error:
        return f"SMB connection error on port {target.port}/tcp: {nt_status_error}"
    return f"SMB connection error on port {target.port}/tcp: session failed"

def nt_status_error_filter(msg):
    for error in NT_STATUS_COMMON_ERRORS:
        if error.lower() in msg.lower():
            return error
    return ""

def abort(msg):
    '''
    This function is used to abort the tool run on error.
    The given error message will be printed out and the tool will abort with exit code 1.
    '''
    print(Colors.red(f"[!] {msg}"))
    sys.exit(1)

def warn(msg):
    print("\n"+Colors.yellow(f"[!] {msg}"))

def yamlize(msg, sort=False, rstrip=True):
    try:
        result = yaml.dump(msg, default_flow_style=False, sort_keys=sort, width=160, Dumper=Dumper)
    except TypeError:
        # Handle old versions of PyYAML which do not support the sort_keys parameter
        result = yaml.dump(msg, default_flow_style=False, width=160, Dumper=Dumper)

    if rstrip:
        return result.rstrip()
    return result

### Argument Processing

def check_arguments():
    '''
    Takes all arguments from argv and processes them via ArgumentParser. In addition, some basic
    validation of arguments is done.
    '''

    global GLOBAL_VERBOSE
    global GLOBAL_SAMBA_LEGACY

    parser = ArgumentParser(description="""This tool is a rewrite of Mark Lowe's enum4linux.pl, a tool for enumerating information from Windows and Samba systems.
            It is mainly a wrapper around the Samba tools nmblookup, net, rpcclient and smbclient. Other than the original tool it allows to export enumeration results
            as YAML or JSON file, so that it can be further processed with other tools.

            The tool tries to do a 'smart' enumeration. It first checks whether SMB or LDAP is accessible on the target. Depending on the result of this check, it will
            dynamically skip checks (e.g. LDAP checks if LDAP is not running). If SMB is accessible, it will always check whether a session can be set up or not. If no
            session can be set up, the tool will stop enumeration.

            The enumeration process can be interupted with CTRL+C. If the options -oJ or -oY are provided, the tool will write out the current enumeration state to the
            JSON or YAML file, once it receives SIGINT triggered by CTRL+C.

            The tool was made for security professionals and CTF players. Illegal use is prohibited.""")
    parser.add_argument("host")
    parser.add_argument("-A", action="store_true", help="Do all simple enumeration including nmblookup (-U -G -S -P -O -N -I -L). This option is enabled if you don't provide any other option.")
    parser.add_argument("-As", action="store_true", help="Do all simple short enumeration without NetBIOS names lookup (-U -G -S -P -O -I -L)")
    parser.add_argument("-U", action="store_true", help="Get users via RPC")
    parser.add_argument("-G", action="store_true", help="Get groups via RPC")
    parser.add_argument("-Gm", action="store_true", help="Get groups with group members via RPC")
    parser.add_argument("-S", action="store_true", help="Get shares via RPC")
    parser.add_argument("-C", action="store_true", help="Get services via RPC")
    parser.add_argument("-P", action="store_true", help="Get password policy information via RPC")
    parser.add_argument("-O", action="store_true", help="Get OS information via RPC")
    parser.add_argument("-L", action="store_true", help="Get additional domain info via LDAP/LDAPS (for DCs only)")
    parser.add_argument("-I", action="store_true", help="Get printer information via RPC")
    parser.add_argument("-R", default=0, const=1, nargs='?', metavar="BULK_SIZE", type=int, help="Enumerate users via RID cycling. Optionally, specifies lookup request size.")
    parser.add_argument("-N", action="store_true", help="Do an NetBIOS names lookup (similar to nbtstat) and try to retrieve workgroup from output")
    parser.add_argument("-w", dest="domain", default='', type=str, help="Specify workgroup/domain manually (usually found automatically)")
    parser.add_argument("-u", dest="user", default='', type=str, help="Specify username to use (default \"\")")
    auth_methods = parser.add_mutually_exclusive_group()
    auth_methods.add_argument("-p", dest="pw", default='', type=str, help="Specify password to use (default \"\")")
    auth_methods.add_argument("-K", dest="ticket_file", default='', type=str, help="Try to authenticate with Kerberos, only useful in Active Directory environment")
    auth_methods.add_argument("-H", dest="nthash", default='', type=str, help="Try to authenticate with hash")
    parser.add_argument("--local-auth", action="store_true", default=False, help="Authenticate locally to target")
    parser.add_argument("-d", action="store_true", help="Get detailed information for users and groups, applies to -U, -G and -R")
    parser.add_argument("-k", dest="users", default=KNOWN_USERNAMES, type=str, help=f'User(s) that exists on remote system (default: {KNOWN_USERNAMES}).\nUsed to get sid with "lookupsids"')
    parser.add_argument("-r", dest="ranges", default=RID_RANGES, type=str, help=f"RID ranges to enumerate (default: {RID_RANGES})")
    parser.add_argument("-s", dest="shares_file", help="Brute force guessing for shares")
    parser.add_argument("-t", dest="timeout", default=TIMEOUT, help=f"Sets connection timeout in seconds (default: {TIMEOUT}s)")
    parser.add_argument("-v", dest="verbose", action="store_true", help="Verbose, show full samba tools commands being run (net, rpcclient, etc.)")
    parser.add_argument("--keep", action="store_true", help="Don't delete the Samba configuration file created during tool run after enumeration (useful with -v)")
    out_group = parser.add_mutually_exclusive_group()
    out_group.add_argument("-oJ", dest="out_json_file", help="Writes output to JSON file (extension is added automatically)")
    out_group.add_argument("-oY", dest="out_yaml_file", help="Writes output to YAML file (extension is added automatically)")
    out_group.add_argument("-oA", dest="out_file", help="Writes output to YAML and JSON file (extensions are added automatically)")
    args = parser.parse_args()

    if not (args.A or args.As or args.U or args.G or args.Gm or args.S or args.C or args.P or args.O or args.L or args.I or args.R or args.N or args.shares_file):
        args.A = True

    if args.A or args.As:
        args.G = True
        args.I = True
        args.L = True
        args.O = True
        args.P = True
        args.S = True
        args.U = True

    if args.A:
        args.N = True

    # Only global variable which meant to be modified
    GLOBAL_VERBOSE = args.verbose

    # Check Workgroup
    # Do not set the domain/workgroup for local auth
    if not args.local_auth and args.domain:
        if not valid_domain(args.domain):
            raise RuntimeError(f"Workgroup/domain '{args.domain}' contains illegal character")

    # Check for RID parameter
    if args.R:
        if not valid_value(args.R, (1,2000)):
            raise RuntimeError("The given RID bulk size must be a valid integer in the range 1-2000")
        if not valid_rid_ranges(args.ranges):
            raise RuntimeError("The given RID ranges should be a range '10-20' or just a single RID like '1199'")

    # Check shares file
    if args.shares_file:
        result = valid_shares_file(args.shares_file)
        if not result.retval:
            raise RuntimeError(result.retmsg)

    # Add given users to list of RID cycle users automatically
    if args.user and args.user not in args.users.split(","):
        args.users += f",{args.user}"

    # Check timeout
    if not valid_value(args.timeout, (1,600)):
        raise RuntimeError("Timeout must be a valid integer in the range 1-600")
    args.timeout = int(args.timeout)

    # Perform Samba version checks - TODO: Can be removed in the future
    samba_version = re.match(r".*(\d+\.\d+\.\d+).*", check_output(["smbclient", "--version"]).decode()).group(1)
    samba_version = tuple(int(x) for x in samba_version.split('.'))
    if samba_version < (4, 15, 0):
        GLOBAL_SAMBA_LEGACY = True

    # While smbclient and rpcclient support '--pw-nt-hash' the net command does not before Samba 4.15.
    # In Samba 4.15 the commandline parser of the various tools were unified so that '--pw-nt-hash' works
    # for this and later versions. An option would be to run the tool in a docker container like a recent
    # Alpine Linux version.
    if GLOBAL_SAMBA_LEGACY and args.nthash and (args.Gm or args.C):
        raise RuntimeError("The -C and -Gm argument require Samba 4.15 or higher when used in combination with -H")

    return args

### Dependency Checks

def check_dependencies():
    missing = []

    for dep in DEPS:
        if not shutil.which(dep):
            missing.append(dep)

    if missing:
        error_msg = (f"The following dependend tools are missing: {', '.join(missing)}\n"
                     "     For Gentoo, you need to install the 'samba' package.\n"
                     "     For Debian derivates (like Ubuntu) or ArchLinux, you need to install the 'smbclient' package.\n"
                     "     For Fedora derivates (like RHEL, CentOS), you need to install the 'samba-common-tools' and 'samba-client' package.")
        raise RuntimeError(error_msg)

### Run!

def main():
    # The user can disable colored output via environment variable NO_COLOR (see https://no-color.org)
    global GLOBAL_COLORS
    if "NO_COLOR" in os.environ:
        GLOBAL_COLORS = False

    print_banner()

    # Check dependencies and process arguments, make sure yaml can handle OrdereDicts
    try:
        Dumper.add_representer(OrderedDict, lambda dumper, data: dumper.represent_mapping('tag:yaml.org,2002:map', data.items()))
        check_dependencies()
        args = check_arguments()
    except Exception as e:
        abort(str(e))

    # Run!
    start_time = datetime.now()
    try:
        enum = Enumerator(args)
        enum.run()
    except RuntimeError as e:
        abort(str(e))
    except KeyboardInterrupt:
        warn("Received SIGINT, aborting enumeration")
    finally:
        if 'enum' in locals():
            result = enum.finish()
            if not result.retval:
                abort(result.retmsg)
    elapsed_time = datetime.now() - start_time

    print(f"\nCompleted after {elapsed_time.total_seconds():.2f} seconds")

if __name__ == "__main__":
    main()
