#***********************
#* NMAP Script Module  *
#***********************

#-----------------------
#--- Import Library ----
#-----------------------
import nmap
import subprocess
import os
import json
import sys
#-----------------------
#--- Variable Define ---
#-----------------------
#--- String variable ---
# Loading from config file
if sys.version_info > (3, 0):
    import configparser
    config = configparser.ConfigParser()
else:
    import ConfigParser
    config = ConfigParser.ConfigParser()
config.read('config.ini')
# get maxcount and depth
MAX_DEPTH = config.get('Common','MAX_DEPTH')
MAX_PAGECOUNT = config.get('Common','MAX_PAGECOUNT')
# Set HYDRA, User Dictionary and Password Dictionary File Path
if os.name == 'nt':
  strHYDRA_Path = os.path.dirname(__file__) + config.get('Windows', 'HYDRA_Path')
  strUserName_Path = config.get('Windows', 'UserName_Dictionary_Path')
  strPassword_Path = config.get('Windows', 'Password_Dictionary_Path')
elif os.name == 'posix':
  strHYDRA_Path = config.get('Linux', 'HYDRA_Path')
  strUserName_Path = config.get('Linux', 'UserName_Dictionary_Path')
  strPassword_Path = config.get('Linux', 'Password_Dictionary_Path')
else:
  print ('OS cannot define!! Variable setting Fail!!')

with open('script.json') as f:
    scriptBonus = json.load(f)[0]

class NSE_Module:

  # HYDRA brute-force Function
  # using HYDRA to scan <service_name>://<target_ip>:<port>, and brute-force with USER_NAME & PASSWORD Dictionary file
  # ip: Targer ip Address
  # ports: Targer service port, it concat with ",". So need to split with "," to extract every ports
  # name: Servive Name, like <ftp>, <ssh> and etc
  # host: host scan info, need to combine script scanning result
  def HYDRA(self, ip, name, host):
    # Dictionary variable for script results (temporary)
    dictScript = {}
    ports = host['ports']
    for port in ports.split(','):
      # for HYDRA, Service string format is: <service_name>://<server_ip>:<port>
      # Using input parameters to concat string for HYDRA 
      strService = name + '://' + ip + ':' + port
      strFile = ip + '_' + port + '.json'
      # Start HYDRA
      # strHYDRA_Path is Global Variable in NSE_Module.py
      # -L <username_list_file>: using username dictionary file, strUserName_Path is Global Variable in NSE_Module.py
      # -P <password_list_file>: using password dictionary file, strPassword_Path is Global Variable in NSE_Module.py
      # -o <output_file>: output to <output_file>. in this case, output file name format is "<ip>_<port>.txt"
      # -b JSON: output result format. in this case output file format is JSON
      processHYDRA = subprocess.Popen([strHYDRA_Path, '-L', strUserName_Path, '-P', strPassword_Path, '-e', 'ns', '-o', strFile, '-b', 'json', strService])
      #processHYDRA = subprocess.Popen([strHYDRA_Path, '-l', 'user', '-p', 'user', '-o', strFile, '-b', 'json', strService])
      processHYDRA.wait()
      # Read result (json file) and Wrtie back to host
      # (In fact, host is dictPortScan variable in main.py)
      if(os.path.isfile(strFile)):
        with open(strFile) as json_file:
          data = json.load(json_file)
          # make sure data is not null
          if not (data['results'] is None):
            dictScript[port] = [] # initail dictScript{}
            for result in data['results']:
              # append on dictScript
              dictScript[port].append({'username': str(result['login']), 'password': str(result['password'])})
              print ('[port:%s] username: ''%s'' password: ''%s''' % (port, result['login'], result['password']))
          else:
            print ('*No executed Results on Port %s*' % (port))
        # remove result file after extract result
        os.remove(strFile)
      else:
        print ('*No file existed!!')
    # Script results update into host(host is dictPortScan[ip][service_name])
    host['scripts'] = dictScript
      
    return 0

  def BRUTE(self, ip, protocol, host):
    # NMAP variable in protocol func()
    nmScan= nmap.PortScanner()
    # Dictionary variable for script results (temporary)
    dictScript = {}
    ports = host['ports']
    # concat port & other nmap command flag
    if protocol not in scriptBonus:
        strArgs = '-p ' + ports + ' -script=' + protocol+'-brute'
    else:
        strArgs = '-p ' + ports + ' -script=' + scriptBonus[protocol]

    # FTP brute force script <ftp-brute>
    nmScan.scan(ip, arguments=strArgs)
    # List Script Name & Scanning result
    for port in nmScan[ip]['tcp']:
      thisDict = nmScan[ip]['tcp'][port]
      if 'script' in thisDict: 
        print ('*Script executed on Port %s*' % (port))
        dictScript[str(port)] = {} # initail dictScript{}
        for thisScript in thisDict['script']:
          # index: nmScan[<IP>][protocols][<port>]['script'][<script name>]
          print ('Script Name ''%s'':%s' % (str(thisScript), thisDict['script'][str(thisScript)]))
          # Add new script scanning record into dictScript[<script name>]:<script result>
          dictScript[str(port)][str(thisScript)] = thisDict['script'][str(thisScript)]
      else:
        print ('*No Script executed on Port %s*' % (port))
    # Script results update into host(host is dictPortScan[ip][service_name], is an dictionary)
    host['scripts'] = dictScript

  def SMB(self, ip, protocol, host):
    nmScan = nmap.PortScanner()
    dictScript = {}
    ports = host['ports']
    strArgs = '-p ' + ports + ' -script=smb-brute,smb-os-discovery'
    nmScan.scan(ip, arguments=strArgs)
    if 'hostscript' in nmScan[ip]:
        print ('*Script executed on Port %s*' % (ports))
        dictScript[str(ports)] = {} # initail dictScript{}
        for index in nmScan[ip]['hostscript']:
            print ('Script Name ''%s'':%s' % (index['id'], index['output']))
            # index: script name in nmScan_SMB[ip]['hostscript'][index num]['id']
            # index: script result in nmScan_SMB[ip]['hostscript'][index num]['output']
            dictScript[str(ports)][str(index['id'])] = index['output']
    else:
        print ('*No Script executed on Port %s*' % (ports))

    host['scripts'] = dictScript
    
    
  # HTTP Authentication Form Script Scan Function
  # Using nmap script <http-auth-finder> to scan HTTP service to find web pages requiring form-based or HTTP-based authentication
  # Results are returned in a table with each url and the detected method
  # ip: ip address
  # ports: all ports of this service
  # host: host scan info, need to combine script scanning result
  def HTTP_Auth_Finder(self, ip, host):
    # >> nmap <ip> -p 80 -script=http-brute,http-form-brute || >> nmap <ip> -p 80 -script=http-*
    # NMAP variable in HTTP func()
    nmScan_HTTP_Auth_Finder = nmap.PortScanner()
    # Dictionary variable for script results (temporary)
    #dictScript = {}
    # return list
    listPath = []
    ports = host['ports']
    # concat port & other nmap command flag
    strArgs = '-p ' + ports + ' -script="http-auth-finder" -script-args="http-auth-finder.maxdepth='+MAX_DEPTH+',http-auth-finder.maxpagecount='+MAX_PAGECOUNT+'"'
    # strArgs = '-p ' + port + ' -script=http-*' # if want to using all of HTTP Script, open this command
    # HTTP brute force script <http-brute>, <http-form-brute>, <http-iis-short-name-brute>,
    # <http-proxy-brute>, <http-wordpress-brute>
    nmScan_HTTP_Auth_Finder.scan(ip, arguments=strArgs)
    # List Script Name & Scanning result
    for port in nmScan_HTTP_Auth_Finder[ip]['tcp']:
      thisDict = nmScan_HTTP_Auth_Finder[ip]['tcp'][port]
      if 'script' in thisDict: 
        #print ('*Script executed on Port %s*' % (port))
        #dictScript[str(port)] = {} # Initail dictScript{}
        for thisScript in thisDict['script']:
          # index: nmScan[<IP>][protocols][<port>]['script'][<script name>]
          #print ('Script Name ''%s'':%s' % (str(thisScript), thisDict['script'][str(thisScript)]))
          # Add new script scanning record into dictScript[<script name>]:<script result>
          #dictScript[str(port)][str(thisScript)] = thisDict['script'][str(thisScript)]
          # split path to extracrt path for execute <http-form-brute> script
          for strTemp in thisDict['script'][str(thisScript)].split('\n'):
            if "withinhost=" in strTemp:
              ip = strTemp.split('withinhost=')[1] # extract ip address
            elif "http" in strTemp:
              tempPath = strTemp.split(ip)[1] # extract url path without protocal+ip <http://ip>
              realPath = tempPath.split()[0] # extract url path without method <FORM, HTTP: Basic>
              if port == 80:
                realPath = str(port) + realPath 
              listPath.append(realPath.strip(':'))
      else:
        print ('*No Script executed on Port %s*' % (port))
    #Script results update into host(host is dictPortScan[ip][service_name])
    #host['scripts'] = dictScript
    
    return listPath
  
  # HTTP_FORM_BRUTE Script Scan Function
  # using nmap script <http-form-brute> to brute force crack password on HTTP service with authantication
  # Arguments:
  #   ip: ip address with url path
  #   ports: all ports of this service
  #   path: url path for nmap script arguments <http-form-brute.path >
  #   host: host scan info, need to combine script scanning result.
  #         Different then other function, <host> data type is array, not a dictionary
  # Return Value:
  #   None
  def HTTP_FORM(self, ip, ports, path, host):
    # >> nmap <ip> -p 80 -script="http-form-brute" -script-args="http-form-brute.path='<path>'"
    # NMAP variable in HTTP_FORM func()
    nmScan_HTTP_FORM = nmap.PortScanner()
    # Dictionary variable for script results (temporary)
    dictScript = {}
    # concat port & other nmap command flag
    if "wordpress" in path:
        strArgs = '-p ' + ports + ' -script="http-wordpress-brute" -script-args="http-wordpress-brute.uri=\'' + path + '\'"'
    else:
        strArgs = '-p ' + ports + ' -script="http-form-brute" -script-args="http-form-brute.path=\'' + path + '\'"'
    nmScan_HTTP_FORM.scan(ip, arguments=strArgs)
    # List Script Name & Scanning result
    for port in nmScan_HTTP_FORM[ip]['tcp']:
      thisDict = nmScan_HTTP_FORM[ip]['tcp'][port]
      if 'script' in thisDict: 
        print ('*Script executed on Port %s, Path:%s*' % (port, path))
        tmpIndexName = str(port)+path # temp variable for index name
        dictScript[tmpIndexName] = {} # Initail dictScript{}
        for thisScript in thisDict['script']:
          # index: nmScan[<IP>][protocols][<port>]['script'][<script name>]
          print ('Script Name ''%s'':%s' % (str(thisScript), thisDict['script'][str(thisScript)]))
          # Add new script scanning record into dictScript[<script name>]:<script result>
          dictScript[tmpIndexName][str(thisScript)] = thisDict['script'][str(thisScript)]
        #Script results update into host(host is dictPortScan[ip][service_name][scripts], is an array)
        host.append(dictScript)
      else:
        print ('*No Script executed on Port %s, Path:%s*' % (port, path))
    
    return 0
  
