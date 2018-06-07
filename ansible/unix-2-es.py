#!/usr/bin/env python3

import sys, time, os, subprocess, sys, json, re, datetime
from datetime import time as timeee
from elasticsearch import Elasticsearch

ES_SERVER = os.getenv('ES_SERVER', '127.0.0.1')
index = os.getenv('ES_INDEX', 'nmap')
ES_INDEX_TYPE = os.getenv('ES_INDEX_TYPE', 'nmap')
MAP_TYPE = os.getenv('MAP_TYPE', 'unix')
d = datetime.date.today()
ES_INDEX_UPDATE = index + '-' + d.strftime('%m%Y')
#ES_INDEX_UPDATE = index + '-052018'
es = Elasticsearch( hosts=[ ES_SERVER ])

def check_time():
    ''' 
    sub_net = ip_net.subnets(new_prefix=24)
    import datetimeist(sub_net)
    20:00 - 06:00 = ip-20-06
    06:00 - 20:00 = ip-06-20
    return('-xx-xx')
    '''
    datenow = datetime.datetime.now()
    timenow = datenow.time()
    start = timeee(6, 0, 0)
    end = timeee(20, 0, 0)

    timestr = datenow.strftime("%y%m%d")
    
    if timenow >= start and timenow < end:
        return(timestr + '-06-20')
    else:
        return(timestr + '-20-06')

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
        
def update_es(ip, result):
    body = {
        "doc": result
    }
    try:
        _id='%s-%s-%s' % (ip, MAP_TYPE, check_time())
        response = es.update(index=ES_INDEX_UPDATE, doc_type=ES_INDEX_TYPE, id=_id, body=body)
    except:
        print("failed: %s" % ip)
parse(sys.argv[1], sys.argv[2])
