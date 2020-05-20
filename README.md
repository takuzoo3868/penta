# penta (PENTest + semi-Automation tool) 

Penta is is Pentest semi-automation tool using Python3. It provides advanced features to extract vuln info found on specific servers. I'm now developing a scanning system using vuln-db.

<p>
<a href="#">
<img src="https://img.shields.io/badge/python-3.7+-blue" alt="Python 3.7+"></a>
<a href="#">
<img src="https://img.shields.io/badge/works%20on-Ubuntu%20%7C%20ArchLinux%20%7C%20MacOS-00AAD4" alt="Platforms"></a>
<!-- <a href="#"><img src="https://img.shields.io/github/v/release/takuzoo3868/penta?include_prereleases" alt="<release>"></a> -->
<a href="https://github.com/takuzoo3868/penta/blob/master/LICENSE">
<img src="https://img.shields.io/github/license/takuzoo3868/penta" alt="License: MIT"></a>
<a href="https://github.com/takuzoo3868/penta/wiki">
<img src="https://img.shields.io/badge/documentation-wiki-lightgray" alt="Wiki"></a>
<a href="#">
<img src="https://img.shields.io/github/languages/code-size/takuzoo3868/penta?color=lightgray"></a>
</p>

<p align="center">
<img width=40% src="https://raw.githubusercontent.com/wiki/takuzoo3868/penta/images/logo_penta.png"></p>

<p align="center">
<img src="https://raw.githubusercontent.com/wiki/takuzoo3868/penta/images/demo.gif" alt="demo" title="IP based scan"></p>

<p align="center">
<img src="https://raw.githubusercontent.com/wiki/takuzoo3868/penta/images/demo2.gif" alt="demo" title="VulnDB construction"></p>


## Installation

### Install requirements

penta requires the following packages.

- Python3.7+
- pipenv

Resolve python package dependency.

```
$ pipenv install
```

If you dislike pipenv

```
$ pip install -r requirements.txt
```

## Usage

```
$ pipenv run start <options>
OR
$ python penta/penta.py <options>
```

### Usage: List options

```
$ pipenv run start -h
usage: penta.py [-h] [-v] [--proxy PROXY]

Penta is Pentest semi-automation tool

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Increase verbosity logging level
  --proxy PROXY  Proxy[IP:PORT]
```

### Main menu

```
======= MAIN MENU ===========================================
 >  Menu list for IP-based scan
    Menu list for building VulnDB
    [Exit]
```

### IP based scan menu

```
======= PENTEST MENU LIST ===================================
 >  Port scan
    Nmap & vuln scan
    Check HTTP option methods
    Grab DNS server info
    Shodan host search
    FTP connect with anonymous
    SSH connect with Brute Force
    Metasploit Frame Work
    Change target host
    [Return]
```


1. Port scanning  
Check the port status of the target host and identify the active service.

2. Nmap  
Check ports by additional means using Nmap.

1. Check HTTP option methods  
Check the methods (e.g. GET,POST) for a target host.

1. Grab DNS server info  
Displays and retrieves DNS whois information and useful records.

2. Shodan host search  
To collect host service info from Shodan.  
Request [Shodan API key](https://developer.shodan.io/) to enable the feature.

1. FTP connect with anonymous  
To check if it has anonymous access activated in port 21.  
FTP users can authenticate themselves using the plain text sign-in protocol (Typically username and password format), but they can connect anonymously if the server is configured to allow it. Anyone can log in to the server if the administrator has allowed an FTP connection with an anonymous login.

1. SSH connect with Brute Force  
To check ssh connection to scan with Brute Force.  
Dictionary data is in `data/dict`.

1. Metasploit Frame Work [Auto Scan is Future Work]  
To check useful msf modules from opened ports.  
Module DB is in `data/msf/module_list.db`.  
Now, I have built a module list DB, and I am moving to a method to use it.

### VulnDB construction menu

```
======= REPORT MENU LIST ====================================
 >  Daily report: CVE,EDB,MSF...
    View  report
    Fetch CVEs
    Fetch Exploits
    Fetch Msf modules
    Menu list for DB
    [Return]
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

## Wiki  
In case you have more question about **penta**, the [wiki](https://github.com/takuzoo3868/penta/wiki/) is very detailed and explains **penta** in great detail.

## License  
Penta is released under the MIT License, see [LICENSE](https://github.com/takuzoo3868/penta/blob/master/LICENSE).