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
| TIMEOUT       | 180					   | Whait Timeout in seconds	     	    |
| ES_SIZE_QUERY | 10					   | Default Elasticsearch hosts query size |
| ROLE          | False                                    | Netbox Role name                       |

#### Usage

```
ansible ...
```