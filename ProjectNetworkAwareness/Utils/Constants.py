import logging
from netaddr import IPNetwork
from math import radians
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.all import *
class Constants(object):
    # HEADER INDEX CONSTANTS
    VERSION = 0
    NUM_FLOWS = 1
    UPTIME = 2
    EPOCH_MS = 3
    EPOCH_NS = 4
    TOTAL_FLOWS = 5
    ENGINE_TYPE = 6
    ENGINE_ID = 7
    SAMPLE_RATE = 8

    # RECORD INDEX CONSTANTS
    SRC_IP = 0
    DST_IP = 1
    HOP_IP = 2
    IF_IN = 3
    IF_OUT = 4
    NUM_PKTS = 5
    L3_BYTES = 6
    START = 7
    END = 8
    SRC_PORT = 9
    DST_PORT = 10
    TCP_FLAGS = 12
    IP_PROT = 13
    SRV_TYPE = 14
    SRC_AS = 15
    DST_AS = 16
    SRC_MASK = 17
    DST_MASK = 18

    # ! - network (= big-endian), H - C unsigned short (2 bytes), I - C unsigned int (4 bytes)
    # NETFLOW V1 HEADER BODY
    NETF_V1H = "!HHIII"
    NETF_V1B = "!IIIHHIIIIHHHBBBBBBI"

    # NETFLOW V5 HEADER BODY
    NETF_V5H = "!HHIIIIBBH"
    NETF_V5H_CHANGED = "!HHIQIIBBH"
    NETF_V5B = "!IIIHHIIIIHHBBBBHHBBH"

    #Classification
    ENTERPRISE_SUBNET = '192.168.0.0/16'
    INSIDE = 0
    OUTSIDE = 1

    #flags
    tcp_flags = ["CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"]
    #protocols_iptype
    protocols_type = {0x00: "IPv6 Hop-by-Hop Option",
                 0x01: "ICMP",
                 0x02: "IGMP",
                 0x03: "GGP",
                 0x04: "IP",
                 0x05: "ST",
                 0x06: "TCP",
                 0x07: "CBT",
                 0x08: "EGP",
                 0x09: "IGP",
                 0x0A: "BBN-RCC-MON",
                 0x0B: "NVP-II",
                 0x0C: "PUP",
                 0x0D: "ARGUS",
                 0x0E: "EMCON",
                 0x0F: "XNET",
                 0x10: "CHAOS",
                 0x11: "UDP",
                 0x12: "MUX",
                 0x13: "DCN-MEAS",
                 0x14: "HMP",
                 0x15: "PRM",
                 0x16: "XNS-IDP",
                 0x17: "TRUNK-1",
                 0x18: "TRUNK-2",
                 0x19: "LEAF-1",
                 0x1A: "LEAF-2",
                 0x1B: "RDP",
                 0x1C: "IRTP",
                 0x1D: "ISO-TP4",
                 0x1E: "NETBLT",
                 0x1F: "MFE-NSP",
                 0x20: "MERIT-INP",
                 0x21: "DCCP",
                 0x22: "3PC",
                 0x23: "IDPR",
                 0x24: "XTP",
                 0xFF: "Unknown"}

    protocols_ports = {21: "FTP",
                 22: "SSH",
                 23: "Telnet",
                 25: "SMTP",
                 37: "Time",
                 43: "WhoIs",
                 53: "DNS",
                 69: "TFTP",
                 80: "HTTP",
                 115: "SFTP",
                 118: "SQL Services",
                 119: "NNTP",
                 123: "NTP (Network Time Protocol)",
                 156: "SQL Service",
                 161: "SNMP",
                 179: "BGP",
                 194: "IRC",
                 443: "HTTP over TLS/SSL",
                 989: "FTP data over TLS/SSL",
                 990: "FTP control over TLS/SSL",
                 993: "IMAP4 over TLS/SSL",
                 995: "POP3 over TLS/SSL"}
    Ether_Fields = [field.name for field in Ether.fields_desc]
    IP_Fields = [field.name for field in IP.fields_desc]
    UDP_Fields = [field.name for field in UDP.fields_desc]
    TCP_Fields = [field.name for field in TCP.fields_desc]
    ARP_Fields = [field.name for field in ARP.fields_desc]
    Ether_types = {0x800: 'IPv4',
                   0x86dd: 'IPv6',
                   0x888e: 'EAP over LAN 802.1X',
                   0x806: 'ARP'}
    # Ether types
    # ['0x800', '0x86dd', '0x888e', '0x806'] abola
    # ['0x800', '0x806'] google
    # ['0x800', '0x806'] facebook
    # ['0x800', '0x86dd', '0x806'] youtube
    # ['0x800', '0x806'] jn
    # ['0x800', '0x806'] 9gag
    ipClassesPrivate = {IPNetwork('10.0.0.0/8'): '8',
                        IPNetwork('172.0.0.0/12'): '12',
                        IPNetwork('192.168.0.0/8'): '16'}

    ipClasses = {#IPNetwork('0.0.0.0/8'): '8',   # 8
                 IPNetwork('128.0.0.0/2'): '16',# 16
                 IPNetwork('192.0.0.0/3'): '24',# 24
                 IPNetwork('224.0.0.0/4'): '0', #Multicasting
                 IPNetwork('240.0.0.0/5'): '0',
                 IPNetwork('255.0.0.0/8'): '8'} #Experimental, other stuff

    localLatitude = radians(40.6303)
    localLongitude = radians(-8.6575)

