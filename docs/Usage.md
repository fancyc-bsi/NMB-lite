---
layout: default
title: Usage
nav_order: 3
---

# Usage
```bash
NMB Mode Options:
  -n, -nessus     Path to the Nessus CSV file
  -c, -config     Path to the configuration file
  -p, -project    Path to the project folder
  -w, -workers    Number of concurrent workers

Remote Connection Options:
  -remote         Remote host to execute commands
  -user           Remote user for SSH connection
  -password       Remote password for SSH connection
  -key            Path to SSH private key file

Nessus Controller Options:
  -mode           Nessus operation mode (deploy, create, launch, monitor, pause, resume, export)
  -policy         Path to Nessus policy file
  -targets        Path to targets file
  -exclude        Path to exclude targets file
  -discovery      Enable host discovery scan
  -name           Project name for the scan

Examples:
  NMB Mode:
    ./nmb -nessus scan.csv -project ./output
    ./nmb -n scan.csv -p ./output -w 20
    ./nmb -n nessus-export.csv -p client_name -c custom_config.json
    ./nmb -n nessus-export.csv -p client_name -remote -user <username> -password <password>
    ./nmb -n nessus-export.csv -p client_name -remote 192.168.1.1 -user <username> -key ~/.id_rsa


  Nessus Controller Mode:
    ./nmb -mode deploy -remote 192.168.1.10 -user admin -password secret -name TestScan -targets hosts.txt
    ./nmb -mode create -remote 192.168.1.10 -user admin -password secret -name TestScan -targets hosts.txt -discovery
    ./nmb -mode launch -remote 192.168.1.10 -user admin -password secret -name TestScan

```