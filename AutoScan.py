#***********************
#*     Main Program    *
#***********************

#-----------------------
#--- Import Library ----
#-----------------------
import nmap
import json
import subprocess
import threading
import time
import os
from argparse import ArgumentParser
from NSE_Module import *  #Costumize Module

if sys.version_info > (3, 0):
    from queue import Queue, Empty
else:
    from Queue import Queue, Empty


#-----------------------
#--- Variable Define ---
#-----------------------
BLUE = '\033[96m'                                                                                                                           
GREEN = '\033[92m'                                                                                                                          
YELLOW = '\033[93m'                                                                                                                           
RED = '\033[0;31m'
ENDC = '\033[0m'
if sys.version_info > (3,0):
    isPy3 = True
else:
    isPy3 = False

#--- Dictionary variable ---
# Host Scan Result (HOST IP->Servive Name->Product,Verison,Port,Script{Result})
dictPortScan = {}
#---- NMAP variable ----
nmScan = nmap.PortScanner()
#---- NSE_Moudule variable ----
nseScript = NSE_Module()

noHydra = ['domain','http','ldap','https','ajp13','mongodb','drda']
exploit = ['ftp','ssh','telnet','smtp','domain','http','pop3', 'netbios-ssn', 
        'microsoft-ds', 'snmp', 'imap', 'ldap', 'https', 'exec', 'login', 'ms-sql-s', 
        'oracle', 'mysql', 'postgresql', 'vnc', 'ajp13', 'mongodb', 'drda']

t_timeout = 600

#--- Arguments variable ---
def argParse():
    parser = ArgumentParser(description='Auto-NMAP Script Scaning Tool using NMAP NSE script to brute-force on open port and service, its based on port scanning result.', epilog='See the about&doc: https://hackmd.io/37N0NZXdQjWqZreM6EIYwQ')
    parser.add_argument('HOST_IP', help='Target HOST IP Address')
    parser.add_argument('-o', help='Using other tools brute-force, <OPT> is tool name. Support tool lists: HYDRA', dest='opt', default='')
    parser.add_argument('-t', help='nmap timeout', dest='time', default='')
    args = parser.parse_args()
    if args.opt == 'HYDRA':
        hydra = True
    else:
        hydra = False

    if args.time != '':
        global t_timeout
        try:
            t_timeout = int(args.time)
        except:
            print(RED+"timeout value should be integer!"+ENDC)
            exit(1)
    return args.HOST_IP, hydra

def writeScanResult(results):
    #deal with os
    osResult = results['scan'][HOST_IP]['osmatch'][0]['osclass']
    platform = []
    for os in osResult:
        newos = os['osfamily'].lower()
        if newos not in platform:
            platform.append(newos)

    targetInfo = results['scan'][HOST_IP]['tcp']
    result = []
    for k in targetInfo.keys():
        item = {'port':int(k), 'service': targetInfo[int(k)]}
        result.append(item.copy())
    os = {'os':platform}
    result.append(os)
    with open('map.json', 'w') as outfile:  
        json.dump(result,outfile,indent=4)


def getProtoName(protocol, port):
    protoName = ''
    if protocol == 'domain':
        protoName = 'dns'
    elif protocol == 'netbios-ssn' or protocol == 'microsoft-ds':
        protoName = 'smb'
    elif protocol == 'https':
        protoName = 'ssl'
    elif protocol == 'exec':
        protoName = 'rexec'
    elif protocol == 'login':
        protoName = 'rlogin'
    elif protocol == 'ms-sql-s':
        protoName = 'mssql'
    elif protocol == 'postgresql':
        protoName = 'postgres'
    elif protocol == 'ajp13':
        protocol = 'ajp'
    elif port == '5000':
        protocol = 'drda'
    else:
        protoName = protocol
    
    return protoName

#-----------------------
#---- main function ----
#-----------------------
def NmapScan():
    print ('Auto-NMAP Script Scaning Tool Starting...')
    # start nmap scan, 1st argument is IP address, 
    # command: nmap -oX - -sV <strIP_Address>
    # nmScan.scan(strIP_Address)
    RawData = nmScan.scan(HOST_IP, arguments='-sV -O')
    # Write NMAP RAW Data into JSON file
    writeScanResult(RawData)
    print('Scan result dumpped to map.json')
    # List all hosts using for loop
    # nmScan.all_hosts() will list all scanned hosts
    # variable:host is one of scanned hosts, value is IP_Address
    for host in nmScan.all_hosts():
        print(YELLOW+'----------------------------------------------------')
        # index: nmScan[<IP>]['hostnames']['name']
        print('Host : %s (%s)' % (host, nmScan[host].hostname())) 
        # index: nmScan[<IP>]['status']['state']
        print('State : %s' % nmScan[host].state()) 
        # Get OS information from [host]['osmatch'][ArrayIndex]['osclass'][ArrayIndex]['osfamily']
        # To Do: If Scanning results had multi os match results, it should change into for loop to get OS info
        strOS = nmScan[host]['osmatch'][0]['osclass'][0]['osfamily']
        dictPortScan[host] = {'OS':strOS}
        # List all protocol on host using for loop
        # nmScan[host].all_protocols() will list all of protocols on host
        # variable:proto is one of scanned hosts, value is tcp || udp
        for proto in nmScan[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            # nmScan[<IP>][proto].keys() will list all keys(key are port number)
            # vaiable:lport are ports
            lport = nmScan[host][proto].keys()
            if isPy3:
                lport = sorted(lport)
            else:
                lport.sort()
            # List all port number & state(up || down) on host using for loop
            # variable:port, type is <int>
            # A host scan info in Dictionary(Servive Name->Product,Verison,Port)
            dictService = {}
            # traverse every port info into dictService
            for port in lport:
                # print infomation
                print ('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))
                # record Product, Name(Service Name) and version
                strProc=nmScan[host][proto][port]['product']
                strName=nmScan[host][proto][port]['name']
                strVer=nmScan[host][proto][port]['version']
                
                if strName not in dictService:
                  # if Service Name is new, add new record into dictService
                  dictService[strName] = {'products':strProc, 'versions':strVer, 'ports': str(port), 'scripts':{}}
                else:
                  # if Service Name is existed, append new record into dictService
                  dictService[strName]['products'] = dictService[strName]['products'] + ';' + strProc
                  dictService[strName]['versions'] = dictService[strName]['versions'] + ';' + strVer
                  dictService[strName]['ports'] = dictService[strName]['ports'] + ',' + str(port)
    print(ENDC)
        
    # append dictService into dictPortScan[<host_IP>]
    dictPortScan[host] = dictService
    
    return dictPortScan

def bruteforcebyService(dictPortScan):
    threadList = []
    serviceList = []

    for ip in dictPortScan.keys():
      if isPy3:
          iters = dictPortScan[ip].items()
      else:
          iters = dictPortScan[ip].iteritems()
      for protocol, info in iters:    
          protoName = getProtoName(protocol,info['ports'])
          if protocol not in exploit or protoName == '':
              continue
    
          print('%s***Start %s brute force scan***%s' %(BLUE, protoName, ENDC)) 
          if HYDRA and protocol not in noHydra:
              t = threading.Thread(target = nseScript.SMB, args = (ip,protoName,info))
          elif protoName == 'http':
               # Using <http-auth-finder> to find authentication form
               # Function returned a list of authentication form, listPath is temporary variable to store returned value
               listPath = nseScript.HTTP_Auth_Finder(ip, info)
               # Initial dictPortScan[ip]['http']['scripts'], data type is array
               info['scripts'] = []
               # In list, format is port/path, so using '/' to split.
               # Reason of split('/', 1) is only need to split port & path. Keep other '/'symbol in path
               for path in listPath:
                   listurl = path.split('/', 1)
                   # Every list after split, send to HTTP_FORM function (IP, port, path, host_info)
                   t = threading.Thread(target=nseScript.HTTP_FORM, 
                     args=(ip, str(listurl[0]), '/' + str(listurl[1]), info['scripts']))
                   threadList.append(t)
                   serviceList.append(protoName+" on path "+str(listurl[1]))
                   try:
                       t.start()
                   except Exception as e:
                       print(RED+str(e)+ENDC)
               continue 
               # To do: 
               #   If found web service, call W3AF to do web vulnerablility scan
               #   HYDRA is support HTTP(S) service, but have to choose http-{head|get|post} method or http-{get|post}-form method
               #   So that's need to customize for HTTP(S) service
               
          elif protoName == 'smb':
              t = threading.Thread(target = nseScript.SMB, args = (ip,protoName,info))
          else:
              t = threading.Thread(target = nseScript.BRUTE, args = (ip,protoName,info))
          
          threadList.append(t)
          serviceList.append(protoName)

          try:
            t.start()
          except Exception as e:
            print(RED+str(e)+ENDC)
    
    for i in range(len(threadList)):
        if threadList[i].isAlive():
            threadList[i].join(timeout=t_timeout)
        print('%s***Complete %s brute force scan***%s'%(BLUE,serviceList[i],ENDC))

    # Wrtie Scanning Result into file (JSON Format)
    with open('scan_result.txt', 'w+') as outfile:  
      json.dump(dictPortScan, outfile)  
      
# exploit with metasploit
def autoExploit(keyword=''):

    cmd = ['python3', 'AutoExploit.py', '-a',HOST_IP, '-n','map.json']
    if keyword != '':
        cmd += '-k '+keyword
    proc = subprocess.Popen(cmd)

if __name__ =="__main__":
    HOST_IP, HYDRA = argParse()
    scanResult = NmapScan()
    #p = threading.Thread(target = autoExploit) 
    #p.start()
    # use nmap script to do brute-force
    bruteforcebyService(scanResult)
    autoExploit()
    #p.join()
    sys.exit()
