# Imports
from argparse import ArgumentParser
from pyshark import FileCapture
import ipaddress
import socket
from ipwhois import IPWhois
from rich.console import Console
from rich.table import Table

# Vars
dest_ip_data = {}

def analyse_pcap(dest_ip_data, data):
    """
        Creates a dict for each destination IP, and populates keys/values for protocol, and dest protocol/port.
        dest_ip_data is empty dict
        data is pyshark packet data.
    """
    for packet in data:
        try:
            if packet.layers[1]._layer_name == "ip":
                """Only look at IP packets"""
                if packet.ip.dst in dest_ip_data:
                    # Add protocol number and port as a string to set
                    dest_ip_data[packet.ip.dst]['protocol_port'].update([str(f"{packet.ip.proto}:{packet[packet.transport_layer].dstport}")])
                else:
                    dest_ip_data[packet.ip.dst] = {}
                    dest_ip_data[packet.ip.dst]['protocol_port'] = set()
                    # Add protocol number and port as a string to set
                    dest_ip_data[packet.ip.dst]['protocol_port'].update([str(f"{packet.ip.proto}:{packet[packet.transport_layer].dstport}")])
        except AttributeError as error:
            pass                  
    return(dict(dest_ip_data))
    
def ip_type(dest_ip_data):
    """Check IP is type gobal and then add ASN/NET data to dict"""
    for ip in dest_ip_data:
        ip_lookup = ipaddress.IPv4Address(ip)
        if not ip_lookup.is_multicast and not ip_lookup.is_private:
            dest_ip_data[ip]['type'] = "Public"
        if ip_lookup.is_private and not ip_lookup.is_reserved:
            dest_ip_data[ip]['type'] = "Private"
        if ip_lookup.is_multicast and not ip_lookup.is_reserved:
            dest_ip_data[ip]['type'] = "Multicast"      
        if ip_lookup.is_reserved:
            dest_ip_data[ip]['type'] = "Reserved"        
        if ip_lookup.is_link_local:
            dest_ip_data[ip]['type'] = "Link Local"
        if ip_lookup.is_loopback:
            dest_ip_data[ip]['type'] = "Loopback"
        if ip_lookup.is_unspecified:
            dest_ip_data[ip]['type'] = "Unspecified"                                       
    return(dict(dest_ip_data))

def ip_dns(dest_ip_data):
    for ip in dest_ip_data:
        if dest_ip_data[ip]['type'] == 'Public' or dest_ip_data[ip]['type'] == 'Private':
            try:
                dns_name = socket.gethostbyaddr(ip)
                dest_ip_data[ip]['dns_name'] = dns_name[0]
            except socket.herror:
                dest_ip_data[ip]['dns_name'] = "Cannot Resolve"
        else:
            dest_ip_data[ip]['dns_name'] = "Skipped"
    return(dest_ip_data)

def ip_whois(dest_ip_data):
    for ip in dest_ip_data:
        if dest_ip_data[ip]['type'] == 'Public':
            ip_whois = IPWhois(ip)
            ip_whois_resolved = ip_whois.lookup_rdap()
            dest_ip_data[ip]['asn'] = ip_whois_resolved['asn']
            dest_ip_data[ip]['asn_country_code'] = ip_whois_resolved['asn_country_code']
            dest_ip_data[ip]['asn_description'] = ip_whois_resolved['asn_description']
            dest_ip_data[ip]['asn_entities'] = ip_whois_resolved['entities']
            dest_ip_data[ip]['network_cidr'] = ip_whois_resolved['network']['cidr']
            dest_ip_data[ip]['network_country'] = ip_whois_resolved['network']['country']
            dest_ip_data[ip]['network_name'] = ip_whois_resolved['network']['name']           
        else:
            dest_ip_data[ip]['asn'] = "N/A"
            dest_ip_data[ip]['asn_country_code'] = "N/A"
            dest_ip_data[ip]['asn_description'] = "N/A"
            dest_ip_data[ip]['asn_entities'] = "N/A"
            dest_ip_data[ip]['network_cidr'] = "N/A"
            dest_ip_data[ip]['network_country'] = "N/A"
            dest_ip_data[ip]['network_name'] = "N/A" 
    return(dest_ip_data)

def add_data(dest_ip_data):
    ip_type(dest_ip_data)
    ip_dns(dest_ip_data)
    ip_whois(dest_ip_data)
    return(dict(dest_ip_data))

def console_print(dest_ip_data):
    console = Console()
    table = Table(title="Destination IP Infomation", show_header=True, header_style="bold magenta", show_lines=True)
    table.add_column("IP", justify="left")
    table.add_column("Type", justify="left", style="dim")
    table.add_column("DNS", justify="left", style="dim")
    table.add_column("Protocol:Port", justify="left", style="dim")
    table.add_column("ASN", justify="left", style="dim")
    table.add_column("ASN Country", justify="left", style="dim")
    table.add_column("ASN Desc", justify="left", style="dim")
    table.add_column("ASN Entities", justify="left", style="dim")
    table.add_column("Network CIDR", justify="left", style="dim")
    table.add_column("Network Country", justify="left", style="dim")
    table.add_column("Network Name", justify="left", style="dim")
    for ip in dest_ip_data:
        table.add_row(
            ip,
            str(dest_ip_data[ip]['type']),
            str(dest_ip_data[ip]['dns_name']),
            str(dest_ip_data[ip]['protocol_port']),
            str(dest_ip_data[ip]['asn']),
            str(dest_ip_data[ip]['asn_country_code']),
            str(dest_ip_data[ip]['asn_description']),
            str(dest_ip_data[ip]['asn_entities']),
            str(dest_ip_data[ip]['network_cidr']),
            str(dest_ip_data[ip]['network_country']),
            str(dest_ip_data[ip]['network_name']),
        )
    console.print(table)

def main():
    parser = ArgumentParser(prog='pcap_dst_info')
    parser.add_argument('pcap_file', help="location of the pcap file to be analysed")
    parser.add_argument('source_ip', help="Source IP of the host which destinations should be analysed")
    args = parser.parse_args()
    data = FileCapture(args.pcap_file, display_filter=f"(ip.src == {args.source_ip} && !ip.dst == {args.source_ip})")
    analyse_pcap(dest_ip_data, data)
    add_data(dest_ip_data)
    #print_formatted_data(dest_ip_data)
    console_print(dest_ip_data)

if __name__ == '__main__':
    main()
