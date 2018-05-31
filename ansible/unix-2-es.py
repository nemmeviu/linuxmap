#!/usr/bin/env python3

import sys, time, os, subprocess, sys, json, re, datetime
from elasticsearch import Elasticsearch


ES_SERVER = os.getenv('ES_SERVER', '127.0.0.1')
index = os.getenv('ES_INDEX', 'nmap')
ES_INDEX_TYPE = os.getenv('ES_INDEX_TYPE', 'nmap')
MAP_TYPE = 'linux'
d = datetime.date.today()
ES_INDEX_UPDATE = index + '-' + d.strftime('%m%Y')
#ES_INDEX_UPDATE = index + '-052018'
es = Elasticsearch( hosts=[ ES_SERVER ])

def parse(var, var_host):

    var = var.replace('|','"')
    var = var.replace('}"','},')
    var = var.replace("[u'","['")
    var = var.replace(", u'", ", '")
    var_host = var_host.replace("[u'","'")
    var_host = var_host.replace(", u'","")
    var_host = var_host.replace("]", "")
    var_host = var_host.replace("'"," ")
    var_host = var_host.split()
#noparsed = str(os.popen("cat noparsed.txt").read())

    var = json.loads(var)
    for i in var_host:
        #var_host2 = str(i+'-180507-06-20')
        update_es(i, var)
        
def update_es(_id, result):
    body = {
        "doc": result
    }
    try:        
        _id = str(_id + "-180531-20-06")
        response = es.update(index=ES_INDEX_UPDATE, doc_type=ES_INDEX_TYPE, id=_id, body=body)
    except:
        print("falla")
parse(sys.argv[1], sys.argv[2])

