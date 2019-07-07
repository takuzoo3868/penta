# penta (PENTest + Automation tool) [![](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/download/releases/3.7.0/) ![t](https://img.shields.io/badge/status-stable-green.svg) [![](https://img.shields.io/github/license/takuzoo3868/penta.svg)](https://github.com/takuzoo3868/penta/blob/master/LICENSE.md)

<p align="center"><img width=40% src="https://raw.githubusercontent.com/wiki/takuzoo3868/penta/images/logo_penta.png"></p>

Penta is is Pentest automation tool using Python3. 

(Future!) It provides advanced features such as metasploit and nexpose to extract vuln info found on specific servers.

![demo](https://raw.githubusercontent.com/wiki/takuzoo3868/penta/images/demo.gif)

### Installation

#### Install requirements

penta requires the following packages.

- Python3.7
- pipenv

Resolve python package dependency.

```
$ pipenv install
```

If you dislike pipenv...

```
$ pip install -r requirements.txt
```

### Usage

```
$ pipenv run start <options>
```

If you dislike pipenv...

```
$ python penta/penta.py
```

#### Usage: List options

```
$ pipenv run start -h
usage: penta.py [-h] [-target TARGET] [-ports PORTS] [-proxy PROXY]

Penta is Pentest automation tool

optional arguments:
  -h, --help      show this help message and exit
  -target TARGET  Specify target IP / domain
  -ports PORTS    Please, specify the target port(s) separated by comma.
                  Default: 21,22,25,80,110,443,8080
  -proxy PROXY    Proxy[IP:PORT]
```

#### Usage: Main menu

```
[ ] === MENU LIST ===========================================
[0] EXIT
[1] Port scanning Default: 21,22,25,80,110,443,8080
[2] Nmap & vuln scanning
[3] Check HTTP option methods
[4] Grab DNS server info
[5] Shodan host search
[6] FTP connect with anonymous
[7] SSH connect with Brute Force
[99] Change target host
```


1. Port scanning  
To check ports for a target. Log output supported.

1. Nmap  
To check ports by additional means using nmap

1. Check HTTP option methods  
To check the methods (e.g. GET,POST) for a target.

1. Grab DNS server info  
To show the info about DNS server.

1. Shodan host search
To collect host service info from Shodan.
Request [Shodan API key](https://developer.shodan.io/) to enable the feature.

1. FTP connect with anonymous
To check if it has anonymous access activated in port 21.
FTP users can authenticate themselves using the plain text sign-in protocol (Typically username and password format), but they can connect anonymously if the server is configured to allow it.
Anyone can log in to the server if the administrator has allowed an FTP connection with an anonymous login.

1. SSH connect with Brute Force
To check ssh connection to scan with Brute Force.
Dictionary data is in `data/dict`.