---
layout: default
title: Usage
nav_order: 3
---

# Usage
```bash
Usage: ./nmb [options]
Options:
  -c string
    	Path to the configuration file (optional) (short)
  -config string
    	Path to the configuration file (optional)
  -key string
    	Path to SSH private key file (optional)
  -n string
    	Path to the Nessus CSV file (short) (default "path/to/nessus.csv")
  -nessus string
    	Path to the Nessus CSV file (default "path/to/nessus.csv")
  -p string
    	Path to the project folder (short) (default "output")
  -password string
    	Remote password for SSH connection
  -project string
    	Path to the project folder (default "output")
  -remote string
    	Remote host to execute commands (optional)
  -user string
    	Remote user for SSH connection
  -w int
    	Number of concurrent workers (short) (default 10)
  -workers int
    	Number of concurrent workers (default 10)

Examples:
$ ./nmb -n nessus-export.csv 
$ ./nmb -n nessus-export.csv -p client_name
$ ./nmb -n nessus-export.csv -p client_name -c custom_config.json
$ ./nmb -n nessus-export.csv -p client_name -remote -user <username> -password <password>
$ ./nmb -n nessus-export.csv -p client_name -remote 192.168.1.1 -user <usename> -key ~/.id_rsa
```