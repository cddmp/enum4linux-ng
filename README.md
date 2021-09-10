<h1 align="center">enum4linux-ng</h1>
<p align="center">
<strong>A next generation version of enum4linux</strong>
</p>
<p align="center">
<img src="https://img.shields.io/badge/python-3.6-blue.svg"/>
<img src="https://img.shields.io/badge/python-3.7-blue.svg"/>
<img src="https://img.shields.io/badge/python-3.8-blue.svg"/>
<img src="https://img.shields.io/badge/python-3.9-blue.svg"/>
<img src="https://img.shields.io/badge/License-GPLv3-green.svg"/>
</p>

enum4linux-ng.py is a rewrite of Mark Lowe's (former Portcullis Labs now Cisco CX Security Labs) enum4linux.pl, a tool for enumerating information from Windows and Samba systems, aimed for security professionals and CTF players. The tool is mainly a wrapper around the Samba tools `nmblookup`, `net`, `rpcclient` and `smbclient`.

I made it for educational purposes for myself and to overcome issues with enum4linux.pl. It has the same functionality as the original tool (though it does some things [differently](#Differences)). Other than the original tool it parses all output of the Samba tools and allows to export all findings as YAML or JSON file. The idea behind this is to allow other tools to import the findings and further process them. It is planned to add new features in the future.

## Features
- support for YAML and JSON export
- colored console output (can be disabled via [NO_COLOR](https://no-color.org/))
- ldapsearch und polenum are natively implemented
- support for legacy SMBv1 connections
- auto detection of IPC signing support
- 'smart' enumeration will automatically disable tests which would otherwise fail
- timeout support
- SMB dialect checks
- IPv6 support (experimental)

## Differences
Some things are implemented differently compared to the original enum4linux. These are the important differences:
- RID cycling is not part of the default enumeration (```-A```) but can be enabled with ```-R```
- parameter naming is slightly different (e.g. ```-A``` instead of ```-a```)

## Credits
I'd like to thank and give credit to the people at former Portcullis Labs (now Cisco CX Security Labs), namely:
- Mark Lowe for creating the original 'enum4linux.pl' (https://github.com/CiscoCXSecurity/enum4linux)
- Richard 'deanx' Dean for creating the original 'polenum' (https://labs.portcullis.co.uk/tools/polenum/)

In addition, I'd like to thank and give credit to:
- Craig 'Wh1t3Fox' West for his fork of 'polenum' (https://github.com/Wh1t3Fox/polenum)

It was lots of fun reading your code! :)

## Legal note
If you use the tool: Don't use it for illegal purposes.

## Run
An example run could look like that:
```$ enum4linux-ng.py -As <target> -oY out```

### Demo
#### Windows Server 2012 R2
This demonstrates a run against Windows Server 2012 R2 standard installation. The following command is being used:

```enum4linux-ng.py 192.168.125.131 -u Tester -p 'Start123!' -oY out```

A user 'Tester' with password 'Start123!' was created. Firewall access was allowed. Once the enumeration is finished, I scroll up so that the results become more clear. Since no other enumeration option is specified, the tool will assume ```-A``` which behaves similar to enum4linux ```-a``` option. User and password are passed in. The ```-oY``` option will export all enumerated data as YAML file for further processing in ```out.yaml```. The tool automatically detects at the beginning that LDAP is not running on the remote host. It will therefore skip any further LDAP checks which would normally be part of the default enumeration.

![Demo](https://github.com/cddmp/misc/blob/master/screencasts/enum4linux-ng/demo1.gif)

#### Metasploitable 2
The second demo shows a run against Metasploitable 2. The following command is being used:

```enum4linux-ng.py 192.168.125.145 -A -C```

This time the ```-A``` and ```-C``` option are used. While the first one behaves similar to enum4linux  ```-a``` option, the second one will enable enumeration of services. This time no credentials were provided. The tool automatically detects that it needs to use SMBv1. No YAML or JSON file is being written. Again I scroll up so that the results become more clear.

![Demo](https://github.com/cddmp/misc/blob/master/screencasts/enum4linux-ng/demo2.gif)

### Usage
```
ENUM4LINUX - next generation

usage: enum4linux-ng.py [-h] [-A] [-As] [-U] [-G] [-Gm] [-S] [-C] [-P] [-O] [-L] [-I] [-R] [-N] [-w WORKGROUP] [-u USER] [-p PW] [-d] [-k USERS] [-r RANGES] [-s SHARES_FILE] [-t TIMEOUT]
                        [-v] [-oJ OUT_JSON_FILE | -oY OUT_YAML_FILE | -oA OUT_FILE]
                        host

This tool is a rewrite of Mark Lowe's enum4linux.pl, a tool for enumerating information from Windows and Samba systems. It is mainly a wrapper around the Samba tools nmblookup, net,
rpcclient and smbclient. Other than the original tool it allows to export enumeration results as YAML or JSON file, so that it can be further processed with other tools. The tool tries to
do a 'smart' enumeration. It first checks whether SMB or LDAP is accessible on the target. Depending on the result of this check, it will dynamically skip checks (e.g. LDAP checks if LDAP
is not running). If SMB is accessible, it will always check whether a session can be set up or not. If no session can be set up, the tool will stop enumeration. The enumeration process can
be interupted with CTRL+C. If the options -oJ or -oY are provided, the tool will write out the current enumeration state to the JSON or YAML file, once it receives SIGINT triggered by
CTRL+C. The tool was made for security professionals and CTF players. Illegal use is prohibited.

positional arguments:
  host

optional arguments:
  -h, --help         show this help message and exit
  -A                 Do all simple enumeration including nmblookup (-U -G -S -P -O -N -I -L). This option is enabled if you don't provide any other option.
  -As                Do all simple short enumeration without NetBIOS names lookup (-U -G -S -P -O -I -L)
  -U                 Get users via RPC
  -G                 Get groups via RPC
  -Gm                Get groups with group members via RPC
  -S                 Get shares via RPC
  -C                 Get services via RPC
  -P                 Get password policy information via RPC
  -O                 Get OS information via RPC
  -L                 Get additional domain info via LDAP/LDAPS (for DCs only)
  -I                 Get printer information via RPC
  -R                 Enumerate users via RID cycling
  -N                 Do an NetBIOS names lookup (similar to nbtstat) and try to retrieve workgroup from output
  -w WORKGROUP       Specify workgroup/domain manually (usually found automatically)
  -u USER            Specify username to use (default "")
  -p PW              Specify password to use (default "")
  -d                 Get detailed information for users and groups, applies to -U, -G and -R
  -k USERS           User(s) that exists on remote system (default: administrator,guest,krbtgt,domain admins,root,bin,none). Used to get sid with "lookupsid known_username"
  -r RANGES          RID ranges to enumerate (default: 500-550,1000-1050)
  -s SHARES_FILE     Brute force guessing for shares
  -t TIMEOUT         Sets connection timeout in seconds (default: 5s)
  -v                 Verbose, show full samba tools commands being run (net, rpcclient, etc.)
  --keep             Don't delete the Samba configuration file created during tool run after enumeration (useful with -v)
  -oJ OUT_JSON_FILE  Writes output to JSON file (extension is added automatically)
  -oY OUT_YAML_FILE  Writes output to YAML file (extension is added automatically)
  -oA OUT_FILE       Writes output to YAML and JSON file (extensions are added automatically)
```

## Installation
There are multiple ways to install the tool. Either the tool comes as a package with your Linux distribution or you need to do a manual install. 

### Automatic Installation
I'm aware of the following Linux distributions which package the tool:

#### Archstrike

```console
$ pacman -S enum4linux-ng
```

#### NixOS
(tested on NixOS 20.9)

```console
$ nix-env -iA nixos.enum4linux-ng
```
### Manual Installation
#### Dependencies
The tool uses the samba clients tools, namely:
- nmblookup
- net
- rpcclient
- smbclient

These should be available for all Linux distributions. The package is typically called `smbclient`, `samba-client` or something similar.

In addition, you will need the following Python packages:
- ldap3
- PyYaml
- impacket

For a faster processing of YAML (optional!) also install (should come as a dependency for PyYaml for most Linux distributions):
- LibYAML

Some examples for specific Linux distributions installations are listed below. Alternatively, distribution-agnostic ways (python pip, python virtual env and Docker) are possible.

#### Linux distribution specific 
For all distribution examples below, LibYAML is already a dependency of the corresponding PyYaml package and will be therefore installed automatically.
##### ArchLinux

```console
#  pacman -S smbclient python-ldap3 python-yaml impacket
```
##### Fedora/CentOS/RHEL
(tested on Fedora Workstation 31)

```console
# dnf install samba-common-tools samba-client python3-ldap3 python3-pyyaml python3-impacket
```

##### Kali Linux/Debian/Ubuntu 
(tested on Kali Linux 2020.1, recent Debian (e.g. Buster) or Ubuntu versions should work, for Ubuntu 18.04 or below use the Docker or Python virtual environment variant)

```console
# apt install smbclient python3-ldap3 python3-yaml python3-impacket
```

#### Linux distribution-agnostic
##### Python pip
Depending on the Linux distribution either `pip3` or `pip` is needed:

```console
$ pip install pyyaml ldap3 impacket
```

Alternative:

```console
$ pip install -r requirements.txt
```

Remember you need to still install the samba tools as mentioned above.

##### Python virtual environment
```console
$ git clone https://github.com/cddmp/enum4linux-ng
$ cd enum4linux-ng
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install wheel
$ pip install -r requirements.txt
```
Then run via:

```python3 enum4linux-ng.py -As <target>```

Remember you need to still install the samba tools as mentioned above. In addition, make sure you run ```source venv/bin/activate``` everytime you spawn a new shell. Otherwise the wrong Python interpreter with the wrong libraries will be used (your system one rather than the virtual environment one).

##### Docker
```console
$ git clone https://github.com/cddmp/enum4linux-ng
$ docker build enum4linux-ng --tag enum4linux-ng
```
Once finished an example run could look like this:
```console
$ docker run -t enum4linux-ng -As <target>
```
## Contribution and Support
Occassionally, the tool will spit out error messages like this:

```Could not <some text here>, please open a GitHub issue```

In that case, please rerun the tool with the ```-v``` and ```--keep``` option. This will allow you to see the exact command which caused the error message. Copy that command, run it in your terminal and redirect the output to a file. Then open a GitHub issue here, pasting the command and attaching the error output file. That helps to debug the issue. Of course, you can debug it yourself and make a pull request.

If the tool is helpful for you, I'm happy if you leave a star!
