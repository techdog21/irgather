# Author Jerry Craft
#
# IRGather is a tool to pull the logs for a linux / windows systems, and put them into a zip file
# so an incident response review can be performed.
#
# 12/21/2022 -- Linux side finished and used for Virco

import os
import sys
import json
import shutil
import psutil
import subprocess
import platform
from datetime import datetime

# global variables
localD = os.getcwd() # get local destination as
localDir =  platform.node()# get computer name
osName = sys.platform # get OS type

def getDiskSpace(fname:str, location:str) -> str:
    "Gather disk space stats so we can ensure we have room"
    try: 
        sfile = open(fname + '/drivespace.txt', 'w')
        total, used, free = shutil.disk_usage(location)
        print("Total: %d GiB" % (total // (2**30)), file=sfile)
        print("Used: %d GiB" % (used // (2**30)), file=sfile)
        print("Free: %d GiB" % (free // (2**30)), file=sfile)
        sfile.close()
    except Exception as err:
        print(f"Unexpected Error: {err=}, {type(err)=}")
    # if not enough space to store files, quit.
    if free < 500000 : print('Exiting not enough space: ', BaseException)
    return location

def getDateTime() -> str:
    "Setup a date and time object"
    now = datetime.now()
    val = now.strftime("%d-%m-%Y-%H-%M-%S-")
    return val

def jsonMe(obj) -> json:
    "Create me a json object"
    json_object = json.dumps(obj, indent = 4)
    return json_object

def saveMe(fname:str, afile:str, obj:json) -> int:
    "Send me data to write, and I will."
    try:
        sfile = open(fname + '/' + afile, 'a')
        print(jsonMe(obj), file=sfile)
        sfile.close()
    except Exception as err:
        print(f"Unexpected Error: {err=}, {type(err)=}")

def getProcess(fname:str):
    "Grab a list of processes and return them."
    sfile = open(fname + '/processes.txt', 'w')
    for proc in psutil.process_iter():
        pDict = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'cmdline', 'connections', 'username', 'status', 'exe', 'open_files'])
        print(jsonMe(pDict), file=sfile)
    sfile.close()

def getServicesWin(fname:str):
    "Grab a list of services from the system."
    sfile = open(fname + '/services.txt', 'w')
    for proc in psutil.win_service_iter():
        print(proc, file=sfile)
    sfile.close()

def printMe(fname:str, aName:str, obj:str) -> None:
    "Print a list of results"
    sfile = open(fname + "/" + aName, 'w')
    if type(obj) == list:
        print('\n'.join(obj), file=sfile)
    else:
        print(obj, file=sfile)
    sfile.close()

def getLinuxServices(fname:str) -> None:
    "List all services in Linux"
    sfile = open(fname + '/linux_services.txt', 'w')
    proc = psutil.pids()
    for item in proc:
        print(psutil.Process(item), file=sfile)
    sfile.close()

def findFiles(fname:str, dir:str, ext:str, fil:str):
    "Find files as necessary"
    # find all GPG files
    sfile = open(fname + fil, 'w')
    for r, d, f in os.walk(dir):
        for file in f:
            if ext in file:
                print(os.path.join(r, file), file=sfile)
    sfile.close()

def cronCopy(fname:str):
    "Copy all CRON / APT files"
    filLst = ['/etc/cron.allow', '/etc/cron.deny', '/etc/crontab', '/etc/anacrontab', '/var/spool/anacron/cron.weekly', '/var/spool/anacron/cron.monthly',
        '/var/spool/anacron/cron.daily', '/var/spool/anacron/cron.hourly', '/etc/apt/sources.list', '/etc/apt/trusted.gpg', '/etc/apt/trustdb.gpg',
        '/etc/resolv.conf', '/etc/hosts.allow', '/etc/hosts.deny', '/etc/centos-release', '/etc/enterprise-release', '/etc/oracle-release', '/etc/redhat-release', 
        '/etc/system-release', '/etc/fstab', '/boot/grub/grub.cfg', '/boot/grub2/grub.cfg', '/etc/issues', '/etc/issues.net',
        '/etc/insserv.conf', '/etc/localtime', '/etc/lsb-release', '/etc/pam.conf', '/etc/rsyslog.conf', '/etc/xinetd.conf', 
        '/etc/netgroup', '/etc/nsswitch.conf', '/etc/ntp.conf', '/etc/yum.conf', '/etc/yum.repos.d', '/etc/chrony.conf', '/etc/chrony', '/etc/passwd', '/etc/group',
        '/etc/timezone', '/etc/localtime']

    dirLst = ['/etc/cron.daily/', '/ect/cron.hourly/', '/etc/cron.weekly/', '/etc/cron.monthly/', '/etc/modprobe.d/', '/etc/modules-load.d/', 
        '/var/spool/at/', '/var/log/messages/', '/var/log/syslog.log','/etc/pam.d', '/etc/rsyslog.d', '/var/log']

    try:
        print("***COPY FILES***")
        currDir = os.getcwd()
        for item in filLst:
            if os.path.exists(item):
                fil = item.split('/')
                x = len(fil)
                shutil.copy(item, currDir + '/' + fname + '/' + fil[x-1])
        for dir in dirLst:
            if os.path.exists(dir): shutil.copytree(dir, fname + dir)

        # list files in path
        dir_list = os.listdir('/etc/')
        printMe(fname, 'cron-file-list.txt', dir_list)
        # find files in a path
        print('***FINDAPT FILES***')
        findFiles(fname, '/etc/apt/trusted.gpg.d/', '*.gpg', '/pgp-files.txt')
        findFiles(fname, '/usr/share/keyrings/', '*.gpg', '/keyrings.txt')
    except IOError as err:
        print(err)

def filewalk(fname):    
        # filewalk and find particular extensions
        print('***FILE WALK***')
        dic = {}
        ext = ('.asp','.aspx', '.phtml', '.php', '.php3', '.php4', '.php5', '.pl', '.cgi', '.jsp', '.jspx', '.jsw', '.jsv', '.jspf', '.cfm', '.cfml','.cfc','.dbm')
        for path, dirc, files in os.walk('/'):
            for name in files:
                if name.endswith(ext):
                    dic.update({'path': path})
                    dic.update({'file': name})
                    saveMe(fname, 'files.txt', dic)

def linuxCommands(fname):
    commands =['who -a', 'dmesg', 'lspci -v', 'ls /home -la', 'ls -R /home', 'ls -R /tmp']
    print('***LINUXCOMMANDS***')
    sfile = open(fname + '/shell-commands-executed.txt', 'w')
    for command in commands:
        process = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, universal_newlines=True)
        output = process.stdout
        print('Command:',output, file=sfile)
        print('\n\n', file=sfile)
    sfile.close()

        

def main():
        # get date and time
        dtime = getDateTime()
        fname = dtime + localDir
        print("Number of cores in system", psutil.cpu_count())
        print('System Running: ', platform.uname())
        # create our directory to safe stuff
        os.mkdir(fname)
        # get the disk space
        print('\n***SPACE***')
        getDiskSpace(fname, '/')
        # get partitions
        print('***PARTITIONS***')
        saveMe(fname, 'partitions.txt', psutil.disk_partitions())
        # create a file with basic processor information
        print('***PROCESSES***')
        getProcess(fname)
        # gather active connections
        print('***NETCONNECTIONS***')
        saveMe(fname, 'network_connections.txt', psutil.net_connections())
        # list users on system
        print('***USERS***')
        saveMe(fname, 'users.txt', psutil.users())
        # boot time
        print('***BOOTTIME***')
        lastboot = psutil.boot_time()
        printMe(fname, 'boottime.txt', datetime.fromtimestamp(lastboot))
        # net addresses
        print('***NETWORKADDRESSES***')
        printMe(fname, 'networking-addresses.txt', psutil.net_if_addrs())
        # gather services information
        print('***SERVICES***')
        if osName == 'win32':
            getServicesWin(fname)
            filewalk(fname)
        elif osName == 'linux':
            getLinuxServices(fname)
            cronCopy(fname)
            filewalk(fname)
            linuxCommands(fname)
        else:
            print('This system is neither windows or linux')

if __name__ == "__main__":
    main()

