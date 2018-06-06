#!/usr/bin/env python3

'''
Hostfootprint Netbox 
====
'''
import os, requests, json, argparse, sys, time, re
import socket, subprocess, logging, datetime

from elasticsearch import Elasticsearch

from multiprocessing import Manager
from multiprocessing.pool import ThreadPool
from threading import Thread, Lock

MAPUSER = os.getenv('MAPUSER', 'root')
MAPPASS = os.getenv('MAPPASS', 'linuxmap')
COUNTRY = os.getenv('COUNTRY', '')
TENANT = os.getenv('TENANT', '')
ROLE = os.getenv('ROLE', '')
SSH_PORT = os.getenv('SSH_PORT', '22')
REDHAT_MAJOR_VERSION = int(os.getenv('REDHAT_MAJOR_VERSION', '6'))
MAP_TYPE = os.getenv('MAP_TYPE', 'linux')

ES_SIZE_QUERY = int(os.getenv('ES_SIZE_QUERY', '500'))

ES_SERVER = os.getenv('ES_SERVER', '127.0.0.1')
index = os.getenv('ES_INDEX', 'nmap')
d = datetime.date.today()
ES_INDEX_SEARCH = index + '-*'
ES_INDEX_UPDATE = index + '-' + d.strftime('%m%Y')

ES_INDEX_TYPE = os.getenv('ES_INDEX_TYPE', 'nmap')

TIMEOUT = int(os.getenv('TIMEOUT', '30'))

if (COUNTRY == '' and TENANT == ''):
    print('Please, create COUNTRY or TENANT env variable')
    sys.exit(2)

es = Elasticsearch( hosts=[ ES_SERVER ])
ansible_ip = []
PROCS = int(os.getenv('PROCS', '50'))
try:
    MPPROCS = int(os.getenv('MPPROCS', '1'))
except:
    print('MPPROCS is a number')
    sys.exit(2)

###### MP
def get_hosts_and_clear():
    result = []
    while len(hosts_shared_lists) > 0:
        result.append(hosts_shared_lists.pop())
    return(result)

def get_nets_and_clear():
    result = []
    while len(nets_shared_lists) > 0:
        result.append(nets_shared_lists.pop())
    return(result)

def do_mproc():
    pool = ThreadPool(processes=MPPROCS)
    #while not shared_info['finalizar'] or len(hosts_shared_lists) > 0:
    while len(hosts_shared_lists) > 0:        
        hosts_args = get_hosts_and_clear()
        if len(hosts_args) > 0:
            pool.map(subproc_exec, hosts_args)
        time.sleep(1)

### END MP
        
# class MakeConn(object):
#     '''
#     check access in host.
#     - if true, call subproc_exec
#     - if false, save the fail status on elasticsearch
#     '''

def update_es(_id, result):

    _id = _id
    # :-)
    
    body = {
        "doc": result
    }

    try:
        response = es.update(
            index=ES_INDEX_UPDATE,
            doc_type=ES_INDEX_TYPE,
            id=_id,
            body=body
        )
    except:
       # print("fail: %s" % _id)
        pass


def get_access(host):
    
    result = {
        'parsed': 3,
        'err': 'not analyzed'
    }

    ip_to_ansible = False
    # get ssh user and pass
    accessmode=False
    host_ip = host['_source']['ip']
    #host_ip = "g100603sv23a"
    try:
        sock = socket.create_connection((host_ip, SSH_PORT), timeout=TIMEOUT)
        if(sock):
            banner = sock.recv(1024)
            banner = banner.decode()
            banner = banner.lower()
            result['banner'] = banner
            
            if banner.find("openssh") != -1 or banner.find("sun_ssh") != -1:
                
                consulta = 'hostname; if PYTHON=$(python2.6 -V 2>&1); then echo $PYTHON; else OTHER_PYTHON=$(python -V 2>&1); if echo $OTHER_PYTHON | egrep "([3][.]|[2][.][6789])" | grep -v grep ; then var=1; else echo "python not-found"; fi; fi; SUNOS="$(uname)" ; if which lsb_release 1>/dev/null && [ "$SUNOS" != "SunOS" ]; then Version=$(lsb_release -i -r | grep -i release) ;elif which oslevel 1>/dev/null && [ "$SUNOS" != "SunOS" ] ;then Version="AIX $(oslevel)" ; else Version=$(cat /etc/release|head -1 ); fi; echo $Version  ' 
                sshpass = "sshpass -p %s ssh -o StrictHostKeyChecking=no -p %s %s@%s '%s'" % (MAPPASS, SSH_PORT, MAPUSER, host_ip , consulta) 
                pipe = subprocess.run(sshpass, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
                if( pipe.returncode == 0):
                    salida = pipe.stdout.decode()
                    salida = salida.split("\n")
                    result['parsed'] = "-5"
                    if(salida[1].find('not-') != -1):
                        #Version de python incorrecta
                        result['err'] = "old python version"
                    else:
                        #version de pytohn correcta
                        result['err'] = "ready to ansible"
                    result['hostname'] = salida[0]
                    result['ssh_PYversion'] = salida[1]
                    result['ssh_SOversion'] = salida[2]
                    # result['ssh_SOversion']
                    matchOS = re.match(r'.*elease:\s+([0-9])[.].*', result['ssh_SOversion'])
                    if (matchOS):
                        try:
                            if (int(matchOS.group(1)) < REDHAT_MAJOR_VERSION):
                                result['obsolete'] = True
                        except:
                            pass
                    #ip_to_ansible = True
                    #ansible_ip.append(host_ip)
                else:
                    result['parsed'] = pipe.returncode
                    result['err'] = pipe.stderr.decode()
            elif banner.find("microsoft") != -1:
                result['parsed'] = "-3"
                result['err'] = "Windows"
            elif banner.find("cisco") != -1:
                result['map_type'] = "network"
                result['err'] = "cisco"
            else:
                result['map_type'] = "network"
                result['err'] = "other"
                
    except socket.timeout as err:
        result['parsed'] = "-1"
        result['err'] = err
    except socket.error as err:
        result['parsed'] = "-2"
        result['err'] = err
    except:
        result['parsed'] = "-3"
        result['err'] = "Random"
    if ip_to_ansible == False:
        update_es(host['_id'], result)

def do_list():
    '''
    Direct callback for when ``--list`` is provided
    Relies on the configuration generated from init to run
    _inventory_group()
    '''
    
    LIST_TERMS = [
        { "exists": { "field": "ip" } },
        { "term": { "map_type": MAP_TYPE } }
    ]

    if COUNTRY != '':
        LIST_TERMS.append(
            { "term": { "g_country": COUNTRY } }
        )
            
    if TENANT != '':
        LIST_TERMS.append(
            { "term": { "g_flag": TENANT } }
        )
            
    if ROLE != '':
        LIST_TERMS.append(
            { "term": { "role": ROLE } }
        )

    body = {
        "from" : 0, "size" : ES_SIZE_QUERY,
        "_source": [ "ip" ],
        "sort" : [
            { "g_last_mod_date" : {"order" : "desc"}},
        ],
        "query": {
            "bool": {
                "must_not": {
                    "exists": { "field": "parsed" }
                },
                "must": LIST_TERMS
            }
        }
    }
    
    res = es.search(
        index=ES_INDEX_SEARCH,
        doc_type=ES_INDEX_TYPE,
        body=body,
        size=ES_SIZE_QUERY,
    )

    ips = []
    for doc in res['hits']['hits']:
        ips.append(doc)
        nets_shared_lists.append(doc)

    t = Thread(target=do_mproc)
    t.start()

    pool = ThreadPool(processes=PROCS)
    while len(nets_shared_lists) > 0:
        nets = get_nets_and_clear()
        if len(nets) > 0:
            pool.map(get_access, nets)
        #pool.map(subproc_exec, nets)
        time.sleep(1)
            
    shared_info['finalizar'] = True
    t.join()
            
def main():

    do_list()

manager = Manager()
hosts_shared_lists = manager.list([])
hosts_error_list = manager.list([])
nets_shared_lists = manager.list([])
shared_info = manager.dict()
        
if __name__ == '__main__':
    main()
