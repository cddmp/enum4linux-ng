# enum4linux-ng
Danger ahead: This tool is currently in beta phase.

enum4linux-ng.py is a rewrite of Mark Lowe's enum4linux.pl.
I mainly made the tool for educational purposes for myself. I tried to implement everything I was missing from the original tool.

Features:
- support for YAML and JSON (pre-parsed output)
- colored console output
- ldapsearch und polenum are natively implemented

I'd like to give credit to Mark Lowe for creating the original enum4linux. In addition, I'd like to thank and give credit to Wh1t3Fox for creating polenum.
It was lots of fun reading the code. :)

If you use the tool: Please, don't use it for illegal purposes.

## Installing dependencies

  `pip install pyyaml python-ldap impacket`

or easily install with

  `pip install -r requirements.txt`
