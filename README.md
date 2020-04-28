# penta (PENTest + semi-Automation tool) [![](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/download/releases/3.7.0/) ![t](https://img.shields.io/badge/status-stable-green.svg) [![](https://img.shields.io/github/license/takuzoo3868/penta.svg)](https://github.com/takuzoo3868/penta/blob/master/LICENSE.md)

<p align="center"><img width=40% src="https://raw.githubusercontent.com/wiki/takuzoo3868/penta/images/logo_penta.png"></p>

Penta is is Pentest semi-automation tool using Python3. 

(Future!) It provides advanced features to extract vuln info found on specific servers. I'm now developing a scanning system using vuln-db.

![demo](https://raw.githubusercontent.com/wiki/takuzoo3868/penta/images/demo.gif)

![demo2](https://raw.githubusercontent.com/wiki/takuzoo3868/penta/images/demo2.gif)

### Installation

#### Install requirements

penta requires the following packages.

- Python3.7
- pipenv

Resolve python package dependency.

```
$ pipenv install
```

If you dislike pipenv

```
$ pip install -r requirements.txt
```

### Usage

```
$ pipenv run start <options>
OR
$ python penta/penta.py <options>
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

(Note: 2020/04/28) For the interactive mode, options will be placed where they are needed for each function.

### Main menu

```
[ ] === MENU LIST ===========================================
[0] EXIT
[1] IP based scan menu
[2] VulnDB construction menu
```

### IP based scan menu

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
[8] Metasploit Frame Work
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

1. Metasploit Frame Work [Auto Scan is Future Work!!!]
To check useful msf modules from opened ports.
Module DB is in `data/msf/module_list.db`.
Now, I have built a module list DB, and I am moving to a method to use it.

### VulnDB construction menu

```
[ ] === MENU LIST ===========================================
[0] Return to MAIN MENU
[1] Generate a daily report: CVE,EDB,MSF...
[2] View a report
[3] Fetch CVEs from nvd.nist
[4] Fetch EDB records from exploit-db
[5] Fetch MSF modules from rapid7
[6] Fetch MSF modules from local
```

1. Generate a daily report  
Retrieves the changed CVE, Metasploit framework module, and the latest ExploitDB records via online and outputs the information to the terminal.

1. View a report  
The vulnerability information recorded in the local DB `vuln_db.sqlite3` is output to the terminal, without retrieving the information.

1. Fetch CVEs  
Download the specified year's CVE from [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) and record it to the DB.

1. Fetch Exploits　(Experimental Features)  
Retrieves exploit information in ExploitDB from the online site. 

1. Fetch Metasploit framework modules  
Each module of msf contains hardcoded CVE information and other information that is useful for scanning. This feature aggregates the information recorded in each module, both online and offline, and provides an association with CVE and EDB.