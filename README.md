# autoExploit ![PyPI - Python Version](https://img.shields.io/pypi/pyversions/Django.svg)
Scan port services with Nmap and do metaexploit

## About
This project is made during my intern in ITRI.<br>
autoExploit uses Nmap to scan ports and do Metasploit after scanning.

## How to Use

- I. Scan and brute force with Nmap, and do exploit with Metasploit
    1. run AutoScan with command `sudo python3 AutoScan.py <ip address>`
    2. edit msf config on `config.ini`

- II. Run without Nmap brute force
    - `python3 AutoExploit.py -a <ip address> -n <nmap scan result> -k <keyword of msf exploit module>`
    - Note that the nmap scan result should be in json format
    - -n and -k arguments are optional

