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
        Path to the configuration file - this overrides the default config (optional)
  -n string
        Path to the Nessus CSV file (short) (default "path/to/nessus.csv")
  -nessus string
        Path to the Nessus CSV file (default "path/to/nessus.csv")
  -p string
        Path to the project folder (short) (default "output")
  -project string
        Path to the project folder (default "output")
  -w int
        Number of concurrent workers (short) (default 5)
  -workers int
        Number of concurrent workers (default 5)

Examples:
$ ./nmb -n nessus-export.csv 
$ ./nmb -n nessus-export.csv -p client_name
$ ./nmb -n nessus-export.csv -p client_name -c custom_config.json
```