# enum4linux-ng
enum4linux-ng.py is a rewrite of Mark Lowe's (former Portcullis Labs/Cisco now CiscoCXSecurityLabs) enum4linux.pl, a tool for enumerating information from Windows and Samba systems, aimed for penetration tester and other security professionals. The tool is mainly a wrapper around the Samba tools `nmblookup`, `net`, `rpcclient` and `smbclient`.

The tool was made for educational purposes for myself and to overcome issues with enum4linux.pl. The tool has the same functionality as the original tool. Other than the original tool it parses the output of the Samba tools already and allows to export all findings as YAML or JSON file. The idea behind this is to make it easier to use the outcome of the tool with other tools. It is planned to add new features in the future.

## Features
- support for YAML and JSON output
- colored console output
- ldapsearch und polenum are natively implemented

## Credits
I'd like to give credit to Mark Lowe for creating the original enum4linux.pl. In addition, I'd like to thank and give credit to Wh1t3Fox for creating polenum.
It was lots of fun reading your code. :)

## Legal note
If you use the tool: Don't use it for illegal purposes.

## Installing dependencies
In order to run the tool, you need the samba clients tools, namely:
- nmblookup
- net
- rpcclient
- smbclient

These should be available for nearly all Linux distributions. The package is typically called `smbclient`, `samba-client` or something similar.

In addition, you will need the following Python packages:
- ldap3
- PyYaml
- impacket

Here are some examples on how to install all dependencies at once:

ArchLinux

```console
pacman -S smbclient python-ldap3 python-yaml impacket
```

Fedora derivates (tested on Fedora Workstation 31)

```console
dnf install samba-common-tools samba-client python3-ldap3 python3-pyyaml python3-impacket
```

Kali Linux (tested on Kali Linux 2020.1, recent Debian versions like Buster should work)

```console
apt install smbclient python3-ldap3 python3-yaml python3-impacket
```

For the Python dependencies, you can of course also use pip. Note, that you might need `pip3` instead of `pip`, depending on your Linux distribution:

```console
pip install pyyaml ldap3 impacket
```

or easily install with

```console
pip install -r requirements.txt
```
