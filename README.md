# linuxmap

Linuxmap is a module used in project [hostfootprint-netbox](https://github.com/nemmeviu/hostfootprint-netbox/).
Linuxmap search for linux/unix hosts inside elasticsearch DB and
execute a ansible setup module to extract informations.

#### Variables for winmap

| env vars      | default value                            | description                            |
|--------------:|:----------------------------------------:|:--------------------------------------:|
| MAPUSER       | _linuxmap,root                           | user(s) separated by "," if many       |
| MAPPASS       | password1,password2                      | Password of users in order. sep by "," |
| ES_SERVER     | 127.0.0.1                                | Elasticsearch Server IP/DNS name       |
| ES_INDEX      | nmap	                                   | Indice elasticsearch                   |
| ES_INDEX_TYPE | nmap	                                   | Type object inside index elasticsearch |
| TENANT        | False                                    | Netbox Tenant slug                     |
| COUNTRY       | False                                    | Netbox Country Name (Region Father)    |
| PROCS         | 20                                       | Number of hosts mappeds in some time   |
| TIMEOUT       | 30					   | Whait Timeout in seconds	     	    |
| ES_SIZE_QUERY | 10					   | Default Elasticsearch hosts query size |
| SSH_PORT      | 22					   | Default ssh port                       |
| ROLE          | False                                    | Netbox Role name                       |
| REDHAT_MAJOR_VERSION | 6                                    | Major version of stable Redhat. If the S.O. release is lower than the value in this variable, will be return one "obsolete = True" key |
| KILL_TIME | 1200                                    | Time for kill all sshpass process (ansible process can be zoombie) |


#### Elasticsearch parsed signal values

| "parsed" key | description |
|-------:|:----------------------------------------:|
| does not exists parsed key | the object has not be processed |
| -5  | sshpass ok. Done to Ansible |
| -3  | Random. Unknow failed |
| Other value | sshpass subprocess error code return. see err value for complete log |

#### Usage

sshpass usage
```
python3 sshpass/sshpass_parse.py
```

ansible ...
```
