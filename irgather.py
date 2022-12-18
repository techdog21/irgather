# Author Jerry Craft
#
# IRGather is a tool to pull the logs for a linux system, and put them into a zip file
# so an incident response review can be performed.
#
#

import os
import sys
import json
import shutil
import psutil
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
        sfile = open(fname + '/' + afile, 'w')
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
        pDict = proc.as_dict()
        print(jsonMe(pDict), file=sfile)
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
    try:
        print("***COPY CRON***")
        if os.path.exists('/etc/cron.allow'): shutil.copyfile('/etc/cron.allow', fname + '/cron.allow')
        if os.path.exists('/etc/cron.deny'): shutil.copy('/etc/cron.deny', fname + '/cron.deny')
        if os.path.exists('/etc/crontab'): shutil.copy('/etc/crontab', fname + '/crontab')
        if os.path.exists('/etc/anacrontab'): shutil.copy('/etc/anacrontab', fname + '/anacrontab')
        if os.path.exists('/etc/cron.daily/'): shutil.copytree('/etc/cron.daily/', fname + '/cron.daily/')
        if os.path.exists('/etc/cron.hourly/'): shutil.copytree('/etc/cron.hourly/', fname + '/cron.hourly/')
        if os.path.exists('/etc/cron.weekly/'): shutil.copytree('/etc/cron.weekly/', fname + '/cron.weekly/')
        if os.path.exists('/etc/cron.monthly/'): shutil.copytree('/etc/cron.monthly/', fname + '/cron.montly/')
        if os.path.exists('/var/spool/anacron/cron.weekly'): shutil.copy('/var/spool/anacron/cron.weekly', fname + '/cron.weekly')
        if os.path.exists('/var/spool/anacron/cron.monthly'): shutil.copy('/var/spool/anacron/cron.monthly', fname + '/cron.monthly')
        if os.path.exists('/var/spool/anacron/cron.daily'): shutil.copy('/var/spool/anacron/cron.daily', fname + '/cron.daily')
        if os.path.exists('/var/spool/anacron/cron.hourly'): shutil.copy('/var/spool/anacron/cron.hourly', fname + '/cron.hourly')
        if os.path.exists('/etc/apt/sources.list'): shutil.copy('/etc/apt/sources.list', fname + '/sources.lst')
        if os.path.exists('/etc/apt/trusted.gpg'): shutil.copy('/etc/apt/trusted.gpg', fname + '/apt-trust.gpg')
        if os.path.exists('/etc/apt/trustdb.gpg'): shutil.copy('/etc/apt/trustdb.gpg', fname + '/apt-trustdb.gpg')
        # list files in path
        dir_list = os.listdir('/etc/')
        printMe(fname, 'cron-file-list.txt', dir_list)
        # find files in a path
        print('***FINDAPT FILES***')
        findFiles(fname, '/etc/apt/trusted.gpg.d/', '*.gpg', '/pgp-files.txt')
        findFiles(fname, '/usr/share/keyrings/', '*.gpg', '/keyrings.txt')

    except IOError as err:
        print(err)

def main():
    try:
        # get date and time
        dtime = getDateTime()
        fname = dtime + localDir
        print("Number of cores in system", psutil.cpu_count())

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
        else:
            getLinuxServices(fname)
            cronCopy(fname)

    except Exception as err:
        print(f"Main Unexpected Error: {err=}, {type(err)=}")

if __name__ == "__main__":
    main()

