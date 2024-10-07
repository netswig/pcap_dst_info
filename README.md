# pcap_dst_info

Get destination IP infomation for a specific host from a PCAP.

## About 

pcap_dst_info is a tool which takes a user provided pcap/pcapng file and a source IP address and provides a list of destination IP's, protocols/ports. Then performing, reverse DNS lookups and gathering whois data for each destination IP.

## Setup & Example

### Windows
```
python -m venv .venv
./venv/Scripts/activate.ps1
pip install -r requirements.txt
python -m pcap_dst_info --help
```
```
python -m pcap_dst_info c:\Users\admin\Downloads\testpcap.pcapng 192.168.1.10
```