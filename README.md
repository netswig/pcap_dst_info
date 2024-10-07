# pcap_dst_info

Get destination IP infomation for a specific host from a PCAP.

## About 

pcap_dst_info is a tool which takes a user provided pcap/pcapng file and a source IP address and provides a list of destination IP's and protocols/ports. The tool then gathers, reverse DNS lookups and whois data for each destination IP and displays in the console.

## Setup & Example

### Windows
#### Setup
```
python -m venv .venv
./venv/Scripts/activate.ps1
pip install -r requirements.txt
python -m pcap_dst_info --help
```
#### Example
```
python -m pcap_dst_info c:\Users\admin\Downloads\testpcap.pcapng 192.168.1.10
```

## Additional Info

### DNS
This tool uses local sockets for DNS resolution, so to correctly resolve private IP address to DNS names its best to run from a device inside the network the PCAP was captured