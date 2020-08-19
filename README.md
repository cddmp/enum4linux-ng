<h1 align="center">enum4linux-ng</h1>
<p align="center">
<strong>A next generation version of enum4linux</strong>
</p>
<p align="center">
<img src="https://img.shields.io/badge/python-3.6-blue.svg"/>
<img src="https://img.shields.io/badge/python-3.7-blue.svg"/>
<img src="https://img.shields.io/badge/python-3.8-blue.svg"/>
<img src="https://img.shields.io/badge/License-GPLv3-green.svg"/>
</p>

enum4linux-ng.py is a rewrite of Mark Lowe's (former Portcullis Labs now CiscoCXSecurityLabs) enum4linux.pl, a tool for enumerating information from Windows and Samba systems, aimed for security professionals and CTF player. The tool is mainly a wrapper around the Samba tools `nmblookup`, `net`, `rpcclient` and `smbclient`.

I made it for educational purposes for myself and to overcome issues with enum4linux.pl. It has the same functionality as the original tool. Other than the original tool it parses all output of the Samba tools and allows to export all findings as YAML or JSON file. The idea behind this is to allow other tools to import the findings and further process them. It is planned to add new features in the future.

## Features
- support for YAML and JSON output
- colored console output
- ldapsearch und polenum are natively implemented
- support for legacy SMBv1 connections

## Credits
I'd like to give credit to Mark Lowe for creating the original enum4linux.pl. In addition, I'd like to thank and give credit to Wh1t3Fox for creating polenum.
It was lots of fun reading your code. :)

## Legal note
If you use the tool: Don't use it for illegal purposes.

## Run
1. [Install dependencies](#Installing-dependencies) (various options)
2. ```$ git clone https://github.com/cddmp/enum4linux-ng && cd enum4linux-ng```
3. Run, e.g. ```$ ./enum4linux-ng.py -As 10.10.10.182 -oY enum.yaml```

If you prefer a Docker based installation, an example run can be found [below](#Docker).

### Demo
This demonstrates a run against Windows Server 2012 R2 standard installation. A user 'Tester' with password 'Start123!' was created. Firewall access was allowed. Once the enumeration is finished, I scroll up so that the results become more clear. The ```-A``` option behaves similar to enum4linux ```-a``` option. User and password are passed in. The ```-oY``` option will export all enumerated data as YAML file for further processing in ```enum.yaml```.

![Demo](https://github.com/cddmp/misc/blob/master/screencasts/enum4linux-ng/demo1.gif)

The second demo shows a run against Metasploitable2. This time no credentials were provided. The tool automatically detects that it needs to use SMBv1. This time also services enumeration is enabled with the ```-C``` option, no YAML or JSON file is being written. Again I scroll up so that the results become more clear.
![Demo](https://github.com/cddmp/misc/blob/master/screencasts/enum4linux-ng/demo2.gif)

## Installing dependencies
The tool uses the samba clients tools, namely:
- nmblookup
- net
- rpcclient
- smbclient

These should be available for nearly all Linux distributions. The package is typically called `smbclient`, `samba-client` or something similar.

In addition, you will need the following Python packages:
- ldap3
- PyYaml
- impacket

Some examples for specific Linux distributions installations are listed below. Alternatively, distribution-agnostic ways (python pip, python virtual env and Docker) are possible.

### Linux distribution specific
#### ArchLinux

```console
#  pacman -S smbclient python-ldap3 python-yaml impacket
```
#### Fedora/CentOS/RHEL
(tested on Fedora Workstation 31)

```console
# dnf install samba-common-tools samba-client python3-ldap3 python3-pyyaml python3-impacket
```

#### Kali Linux/Debian/Ubuntu 
(tested on Kali Linux 2020.1, recent Debian versions like Buster should work)

```console
# apt install smbclient python3-ldap3 python3-yaml python3-impacket
```

### Linux distribution-agnostic
#### Python pip
Depending on the Linux distribution either `pip3` or `pip` is needed:

```console
$ pip install pyyaml ldap3 impacket
```

Alternative:

```console
$ pip install -r requirements.txt
```

Remember you need to still install the samba tools as mentioned above.

#### Python virtual environment
```console
$ git clone https://github.com/cddmp/enum4linux-ng
$ cd enum4linux-ng
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

Remember you need to still install the samba tools as mentioned above.
#### Docker
```console
$ git clone https://github.com/cddmp/enum4linux-ng
$ docker build enum4linux-ng --tag enum4linux-ng
```
Once finished an example run could look like this:
```console
$ docker run -t enum4linux-ng -As 1.2.3.4 
```
