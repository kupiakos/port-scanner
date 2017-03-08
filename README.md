# port-scanner
A simple port scanning utility using Scapy.

## Features
 - ICMP, TCP SYN, and UDP scan support
 - Multiple host scanning
 - Multiple port selection
 - Friendly port names
 - Input file for hostnames
 - Basic HTML Report

## Usage
An example:

    ./scanner.py -S 80,443 www.google.com,10.11.102.23 -o report.html

This runs a TCP SYN scan on ports 80 and 443 on `www.google.com` and `10.11.102.23`.
A simple HTML report will be written to `report.html`.

Run `./scanner.py --help` for detailed usage.
You may need to run `pip3 install -r requirements.txt` first.

Examples of valid host specifications:
`www.google.com`, `10.11.207.0/23`, `10.11.207.2-254`.
Multiple specifications can be provided, separated by commas.

Port ranges like `10-23`, as well as multiple ports, `80,443` are supported.
In addition, "friendly" port names can be provided as well:
`http,https,ftp`.

