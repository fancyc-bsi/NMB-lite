---
layout: default
title: Home
nav_order: 1
permalink: /
---

# NMB Documentation

Welcome to the official documentation for NMB. This documentation will guide you through the various features, configurations, and usage of NMB.

## Overview

NMB is a versatile tool designed for pentesters. It automates the process of running multiple network scanning and enumeration tools, parses the results, and generates comprehensive reports. NMB is particularly useful for:

- Automating the scanning process for multiple hosts and services.
- Verifying the presence of vulnerabilities using configurable verification words.
- Generating detailed markdown and HTML reports with scan results, including screenshots.

## Getting started

To use NMB, simply download the binary from the release tab on github (https://github.com/fancyc-bsi/NMB-lite)

That's it, no other dependencies are required!

## Features

- **Concurrent Scanning:** Run multiple scans concurrently using a worker pool to speed up the scanning process.
- **Customizable Configurations:** Easily configurable plugins and scan parameters through a configuration file.
- **Screenshot Integration:** Automatically captures screenshots of scan results for visual verification.
- **Retry Mechanism:** Implements a retry mechanism for `nmap` scans with the `-Pn` option if the initial scan fails.
- **Report Generation:** Generates markdown and HTML reports of the scan results.
- **Remote Execution** Executes verification steps on remote host instead of locally if selected.

## Configuration

### Configuration File

The configuration file is a JSON file that specifies the plugins, scan types, parameters, and verification words. Below is an example configuration:

```json
{
    "plugins": {
        "AMQP_Info_Checks": {
            "ids": [
                "87733"
            ],
            "parameters": "--script amqp-info {host} -p {port}",
            "scan_type": "nmap -T4 --host-timeout 300s",
            "verify_words": [
                "up",
                "amqp"
            ]
        },
}
```
