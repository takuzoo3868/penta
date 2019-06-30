# penta (PENTest + Automation tool) [![](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/download/releases/3.7.0/) ![t](https://img.shields.io/badge/status-stable-green.svg) [![](https://img.shields.io/github/license/takuzoo3868/penta.svg)](https://github.com/takuzoo3868/penta/blob/master/LICENSE.md)

<p align="center"><img width=40% src="https://github.com/takuzoo3868/penta/blob/master/assets/img/logo_penta.png"></p>

Penta is is Pentest automation tool using Python3. 

(Future!) It provides advanced features such as metasploit and nexpose to extract vuln info found on specific servers.

<img src="assets/img/demo.gif", width="1000">

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
[1] Check opened port(s) 	Default: 21,22,25,80,110,443,8080
[2] Port scanning
[3] Nmap
[4] Check HTTP option methods
[5] Grab DNS server info
[ ] =========================================================
```


1. Check opened port(s)  
To check the open port(s) for a target. 

1. Port scanning  
To check ports for a target. Log output supported.

1. Nmap  
To check ports by additional means using nmap

1. Check HTTP option methods  
To check the methods (e.g. GET,POST) for a target.

1. Grab DNS server info  
To show the info about DNS server.

1. (TBA)