#!/usr/bin/env python3

'''
Hostfootprint Netbox 
====

# Ansible Dynamic Inventory to pull hosts from Elasticsearch

'''
import os, requests, json, argparse, sys, time, re
import socket, subprocess, logging, datetime

from elasticsearch import Elasticsearch

MAPUSER = os.getenv('MAPUSER', 'root')
MAPPASS = os.getenv('MAPPASS', 'linuxmap')
COUNTRY = os.getenv('COUNTRY', '')
TENANT = os.getenv('TENANT', '')
ROLE = os.getenv('ROLE', '')
SSH_PORT = os.getenv('SSH_PORT', '22')
REDHAT_MAJOR_VERSION = int(os.getenv('REDHAT_MAJOR_VERSION', '6'))

ES_SIZE_QUERY = int(os.getenv('ES_SIZE_QUERY', '500'))

ES_SERVER = os.getenv('ES_SERVER', '127.0.0.1')
index = os.getenv('ES_INDEX', 'nmap')
d = datetime.date.today()
ES_INDEX_SEARCH = index + '-*'
ES_INDEX_UPDATE = index + '-' + d.strftime('%m%Y')

ES_INDEX_TYPE = os.getenv('ES_INDEX_TYPE', 'nmap')
MAP_TYPE = os.getenv('MAP_TYPE','unix')

TIMEOUT = int(os.getenv('TIMEOUT', '30'))
es = Elasticsearch( hosts=[ ES_SERVER ])

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
        
        LIST_TERMS = [
            { "exists": { "field": "ip" } },
            { "term": { "map_type": MAP_TYPE } },
            { "term": { "parsed": "-5" } },            
        ]
        
        LIST_TERMS_OBSOLETE = [
            { "exists": { "field": "ip" } },
            { "exists": { "field": "obsolete" } },
            { "term": { "parsed": "-5" } },            
            { "term": { "map_type": MAP_TYPE } },
        ]
        
        LIST_NOT_TERMS = [
            { "exists": { "field": "obsolete" } },            
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

        body_stable = {
            "from" : 0, "size" : ES_SIZE_QUERY,
            "_source": [ "ip" ],
            "sort" : [
                { "g_last_mod_date" : {"order" : "desc"}},
            ],
            "query": {
                "bool": {
                    "must": LIST_TERMS,
                    "must_not": LIST_NOT_TERMS,
                }
            }
        }

        body_obsolete = {
            "from" : 0, "size" : ES_SIZE_QUERY,
            "_source": [ "ip" ],
            "sort" : [
                { "g_last_mod_date" : {"order" : "desc"}},
            ],
            "query": {
                "bool": {
                    "must": LIST_TERMS_OBSOLETE
                }
            }
        }

        res = es.search(
            index=ES_INDEX_SEARCH,
            doc_type=ES_INDEX_TYPE,
            body=body_stable,
            size=ES_SIZE_QUERY,
        )
        
        ips_stable = []
        for doc in res['hits']['hits']:
            ips_stable.append(doc['_source']['ip'])            
            
        res = es.search(
            index=ES_INDEX_SEARCH,
            doc_type=ES_INDEX_TYPE,
            body=body_obsolete,
            size=ES_SIZE_QUERY,
        )

        ips_obsolete = []
        for doc in res['hits']['hits']:
            ips_obsolete.append(doc['_source']['ip'])

        self.config = {
            "unix_stable": {
                "hosts": ips_stable,
                "vars": {
                    "ansible_connection": "ssh",
                    "ansible_ssh_user": MAPUSER,
                    "ansible_ssh_pass": MAPPASS,
                    "host_key_checking": "false"
                }
            },
            "unix_obsolete": {
                "hosts": ips_obsolete,
                "vars": {
                    "ansible_connection": "ssh",
                    "ansible_ssh_user": MAPUSER,
                    "ansible_ssh_pass": MAPPASS,
                    "host_key_checking": "false",
                    "ansible_python_interpreter": "/usr/local/bin/python2.6",
                }
            }
        }

        return(self.config)

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
                return({ groups: host })
        else:
            sys.exit(0)
            
        #device = [i for i in self.client.devices.get()
        #          if host in i['hostname']][0]
        #attributes = device['attributes']
        #attributes.update({'site_id': device['site_id'], 'id': device['id']})
        #return attributes

    def nothing(self, group):
        pass
        
        #self.config['linux']['hosts'] = ansible_ip   
        #return(self.config)
    
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
        action='store'
        #dest="_host"
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
        full = client.do_list()
        print(full)
        #print(len(full['linux_obsolete']['hosts']))
        #print(full['linux_obsolete']['hosts'][0])
        #print(len(full['linux_stable']['hosts']))        
        #print(client.nothing('linux'))
    elif args.host:
        print(client.do_host(args.host))        

if __name__ == '__main__':
    main()
