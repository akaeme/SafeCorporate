from struct import pack, pack_into, unpack
from array import array
from netaddr import IPAddress
from Utils import Constants
from Utils import Utils
constants = Constants.Constants()
utils = Utils.Utils()

version = 5
num_flows = int(input("Enter number of flows: "))
uptime = int(input("Enter device uptime (millis): "))
epoch_ms = int(input("Enter system clock in millis (since Epoch): "))
epoch_ns = int(input("Residual nanoseconds (since Epoch): "))
total_flows = int(input("Total flows seen since boot: "))
engine_type = int(input("Engine type: "))
engine_id = int(input("Engine ID: "))
sample_rate = int(input("Sampling Interval: "))

pktPayload = array('B', (24 + (num_flows * 48)) * b"\0")

pack_into(constants.NETF_V5H, pktPayload, 0, version, num_flows, uptime, epoch_ms, epoch_ns, total_flows,
          engine_type, engine_id, sample_rate)

offset = 24

for i in range(num_flows):
    "=== Flow #" + str(i + 1) + " ==="
    srcIP = int(IPAddress(input("Source IP: ")))
    dstIP = int(IPAddress(input("Destination IP: ")))
    nextHop = int(IPAddress(input("IP of next hop: ")))
    snmpIn = int(input("SNMP Input Index: "))
    snmpOut = int(input("SNMP Output Index: "))
    numPkts = int(input("Number of Packets in Flow: "))
    L3Bytes = int(input("Total Layer 3 Bytes: "))
    flowStart = int(input("Flow Start Time: "))
    flowEnd = int(input("Flow End Time: "))
    srcPort = int(input("Source Port: "))
    dstPort = int(input("Destination Port: "))
    #tcpFlags = int(input("TCP Flags: "))
    tcpFlags = utils.chooseTCPFlags()
    #ipProt = int(input("IP Protocol Type: "))
    ipProt = utils.getIPTypeHex(input("IP Protocol Type: "))
    tos = int(input("Type of Service (ToS): "))
    srcAS = int(input("Source AS: "))
    dstAS = int(input("Destination AS: "))
    srcMask = int(input("Source Netmask (CIDR): "))
    dstMask = int(input("Destination Netmask (CIDR): "))

    pack_into(constants.NETF_V5B, pktPayload, offset, srcIP, dstIP, nextHop,
              snmpIn, snmpOut, numPkts, L3Bytes, flowStart, flowEnd, srcPort, dstPort, 0, tcpFlags, ipProt,
              tos, srcAS, dstAS, srcMask, dstMask, 0)
    offset += 48

fileName = open(input("Output File: "), "wb")
fileName.write(pktPayload)
fileName.close()