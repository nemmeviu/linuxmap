#!/usr/bin/env python3

'''
Hostfootprint Netbox 
====

# Ansible Dynamic Inventory to pull hosts from Elasticsearch

'''
import os, requests, json, argparse, sys, time
import socket, subprocess, logging, datetime

from elasticsearch import Elasticsearch

from multiprocessing import Manager
from multiprocessing.pool import ThreadPool
from threading import Thread, Lock

LISTMAPUSER = os.getenv('MAPUSER', 'localhost/_winmap,domain/Administrator').split(',')
LISTMAPPASS = os.getenv('MAPPASS', 'password1,password2').split(',')
if len(LISTMAPUSER) != len(LISTMAPPASS):
    print('MAPUSER and MAPPASS dont have some size of values')
    sys.exit(2)
COUNTRY = os.getenv('COUNTRY', '')
TENANT = os.getenv('TENANT', '')
ROLE = os.getenv('ROLE', '')

ES_SIZE_QUERY = int(os.getenv('ES_SIZE_QUERY', '10'))

ES_SERVER = os.getenv('ES_SERVER', '127.0.0.1')

index = os.getenv('ES_INDEX', 'nmap')
d = datetime.date.today()
ES_INDEX_SEARCH = index + '-*'
ES_INDEX_UPDATE = index + '-' + d.strftime('%m%Y')

ES_INDEX_TYPE = os.getenv('ES_INDEX_TYPE', 'nmap')
MAP_TYPE = 'windows'

TIMEOUT = int(os.getenv('TIMEOUT', '180'))

if (COUNTRY == '' and TENANT == ''):
    print('Please, create COUNTRY or TENANT env variable')
    sys.exit(2)

es = Elasticsearch( hosts=[ ES_SERVER ])    

PROCS = int(os.getenv('PROCS', '10'))
try:
    MPPROCS = int(os.getenv('MPPROCS', '10'))
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
    while not shared_info['finalizar'] or len(hosts_shared_lists) > 0:
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
        print("fail: %s" % _id)


def get_access(host):
    
    result = {
        'parsed': 3,
        'err': 'not analyzed'
    }

    # get ssh user and pass
    print(LISTMAPUSER)
    accessmode=False                

    try:
        sock = socket.create_connection((host, port), timeout=30)
    except:
        result['parsed'] = 4
        result['err'] = "without access"
            
    update_es(host['_id'], result)

    print(LISTMAPUSER)
    accessmode=False

    listpass = 0    
    for x in LISTMAPUSER:
        mapuser = x + '%' + LISTMAPPASS[listpass]
        conntest = 'sshpass -p %s ssh %s@%s exit' % (
            mapuser,
            host['_source']['ip'],
            '''SELECT Caption from Win32_OperatingSystem'''            
        )
        
    

def warning(*objs):
    print("WARNING: ", *objs, file=sys.stderr)

class EsInventory(object):
    '''Elastic Search Client object for gather inventory'''

    def __init__(self):
        self.config = dict()

    def _config_default(self):
        default_yaml = '''
        ---
        routers:
          query: deviceType=ROUTER
        switches:
          query: deviceType=SWITCH
        firewalls:
          query: deviceType=FIREWALL
        '''
        self.config = yaml.safe_load(dedent(default_yaml))

    def do_list(self):
        '''Direct callback for when ``--list`` is provided

        Relies on the configuration generated from init to run
        _inventory_group()
        '''

        COUNTRY = os.getenv('COUNTRY', '')
        TENANT = os.getenv('TENANT', '')
        ROLE = os.getenv('ROLE', '')
        
        headers={'Accept': 'application/json', 'Content-type': 'application/json'}
        LIST_TERMS = [
            { "exists": { "field": "ip" } },
            { "term": { "map_type": "linux" } }
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

        payload = {
            "from" : 0, "size" : 200,
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

        payload = json.dumps(payload)
        r = requests.get(
                'http://127.0.0.1:9200/nmap-*/_search',
            headers=headers,
            data=payload
        )

        res = json.loads(r.text)
        ips = []
        for doc in res['hits']['hits']:
            ips.append(doc)
        self.ips = ips

        self.config = {
            "linux": {
                "hosts": self.ips,
                "vars": {
                    "ansible_connection": "ssh",
                    "ansible_ssh_user": "root",
                    "ansible_ssh_pass": "coisalinda",
                    "host_key_checking": "false"
                }
            }
        }
        #self.config = {
        #    "linux": self.ips,
        #}

    def do_host(self, host):
        return(self._hostvars(host))
        #return json.dumps(self._hostvars(host))

    def _hostvars(self, host):
        '''Return dictionary of all device attributes

        Depending on number of devices in NSoT, could be rather slow since this
        has to request every device resource to filter through
        '''
        self.do_list()
        for groups in self.config.keys():
            if host in self.config[groups]['hosts']:
                return( { groups: host })
        else:
            sys.exit(0)
            
        #device = [i for i in self.client.devices.get()
        #          if host in i['hostname']][0]
        #attributes = device['attributes']
        #attributes.update({'site_id': device['site_id'], 'id': device['id']})
        #return attributes

    def nothing(self, group):
        
        for host in self.config[group]['hosts']:
            nets_shared_lists.append(host)

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
            
            
        return(self.config)
    
def parse_args():
    #desc = __doc__.splitlines()[4]  # Just to avoid being redundant

    # Establish parser with options and error out if no action provided
    parser = argparse.ArgumentParser(
        description='rock',
        conflict_handler='resolve',
    )

    # Arguments
    #
    # Currently accepting (--list | -l) and (--host | -h)
    # These must not be allowed together
    parser.add_argument(
        '--list', '-l',
        help='Print JSON object containing hosts to STDOUT',
        action='store_true',
        dest='_list',  # Avoiding syntax highlighting for list
    )

    parser.add_argument(
        '--host', '-h',
        help='Print JSON object containing hostvars for <host>',
        action='store',
    )
    args = parser.parse_args()

    if not args._list and not args.host:  # Require at least one option
        parser.exit(status=1, message='No action requested\n')

    if args._list and args.host:  # Do not allow multiple options
        parser.exit(status=1, message='Too many actions requested\n')
    return args

def main():
    #Set up argument handling and callback routing
    args = parse_args()
    client = EsInventory()

    # Callback condition
    if args._list:
        client.do_list()
        print(client.nothing('linux'))
    elif args.host:
        #print(client.do_host(args.host))
        print(client.do_host(args.host))        

manager = Manager()
hosts_shared_lists = manager.list([])
hosts_error_list = manager.list([])
nets_shared_lists = manager.list([])
shared_info = manager.dict()
        
if __name__ == '__main__':
    main()
