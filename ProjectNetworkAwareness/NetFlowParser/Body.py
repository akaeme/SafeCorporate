from Utils import Utils
from netaddr import *

utils = Utils.Utils()
class Body(object):
    # Body
    srcIP = None
    dstIP = None
    nextHop = None
    snmpIn = None
    snmpOut = None
    numPkts = None
    L3Bytes = None
    flowStart = None
    flowEnd = None
    srcPort = None
    dstPort = None
    tcpFlags = None
    ipProt = None
    tos = None
    srcAS = None
    dstAS = None
    srcMask = None
    dstMask = None
    srcNetwork = None
    dstNetwork = None

    def __init__(self, version):
        super(Body, self).__init__()
        self.version = version

    def __dict__(self):
        if self.version == 1:
            return {'srcIP'     :   self.srcIP.bin,
                    'dstIP'     :   self.dstIP.bin,
                    'nextHop'   :   self.nextHop.bin,
                    'snmpIn'    :   bin(self.snmpIn),
                    'snmpOut'   :   bin(self.snmpOut),
                    'numPkts'   :   bin(self.numPkts),
                    'L3Bytes'   :   bin(self.L3Bytes),
                    'flowStart' :   bin(self.flowStart),
                    'flowEnd'   :   bin(self.flowEnd),
                    'scrPort'   :   bin(self.srcPort),
                    'dstPort'   :   bin(self.dstPort),
                    'tcpFlags'  :   bin(self.tcpFlags),
                    'ipProt'    :   bin(self.ipProt),
                    'tos'       :   bin(self.tos)}
        else:
            return {'srcIP'     :   self.srcIP.bin,
                    'dstIP'     :   self.dstIP.bin,
                    'nextHop'   :   self.nextHop.bin,
                    'snmpIn'    :   bin(self.snmpIn),
                    'snmpOut'   :   bin(self.snmpOut),
                    'numPkts'   :   bin(self.numPkts),
                    'L3Bytes'   :   bin(self.L3Bytes),
                    'flowStart' :   bin(self.flowStart),
                    'flowEnd'   :   bin(self.flowEnd),
                    'scrPort'   :   bin(self.srcPort),
                    'dstPort'   :   bin(self.dstPort),
                    'tcpFlags'  :   bin(self.tcpFlags),
                    'ipProt'    :   bin(self.ipProt),
                    'tos'       :   bin(self.tos),
                    'srcAs'     :   bin(self.srcAS),
                    'dstAs'     :   bin(self.dstAS),
                    'srcMask'   :   bin(self.srcMask),
                    'dstMask'   :   bin(self.dstMask)}

    def setBody(self, srcIP, dstIP, nextHop, snmpIn, snmpOut, numPkts, L3Bytes, flowStart, flowEnd, srcPort, dstPort, tcpFlags=None, ipProt=None,
                tos=None, srcAS = None, dstAS = None, srcMask = None, dstMask = None):
        if self.version == 1:
            self.srcIP = IPAddress(srcIP)
            self.dstIP = IPAddress(dstIP)
            self.nextHop = IPAddress(nextHop)
            self.snmpIn = snmpIn
            self.snmpOut = snmpOut
            self.numPkts = numPkts
            self.L3Bytes = L3Bytes
            self.flowStart = flowStart
            self.flowEnd = flowEnd
            self.srcPort = srcPort
            self.dstPort = dstPort
            self.tcpFlags = tcpFlags
            self.ipProt = ipProt
            self.tos = tos
        elif self.version == 5:
            self.srcIP = IPAddress(srcIP)
            self.dstIP = IPAddress(dstIP)
            self.nextHop = IPAddress(nextHop)
            self.snmpIn = snmpIn
            self.snmpOut = snmpOut
            self.numPkts = numPkts
            self.L3Bytes = L3Bytes
            self.flowStart = flowStart
            self.flowEnd = flowEnd
            self.srcPort = srcPort
            self.dstPort = dstPort
            self.tcpFlags = tcpFlags
            self.ipProt = ipProt
            self.tos = tos
            self.srcAS = srcAS
            self.dstAS = dstAS
            self.srcMask = srcMask
            self.dstMask = dstMask
            #Inference
            self.srcNetwork = IPNetwork(self.srcIP)
            self.srcNetwork.prefixlen = self.srcMask
            self.dstNetwork = IPNetwork(self.dstIP)
            self.dstNetwork.prefixlen = self.dstMask
        else:
            print("Unsupported Version")

    def dumpBody(self):
        print("==== NetFlow Record Dump ====")
        print("Source: " + str(self.srcIP))
        print("Destination: " + str(self.dstIP))
        print("Next Hop: " + str(self.nextHop))
        print("SNMP Input Interface: " + str(self.snmpIn))
        print("SNMP Output Interface: " + str(self.snmpOut))
        print("Number of Packets in Flow: " + str(self.numPkts))
        print("Total Layer 3 Bytes in Flow: " + str(self.L3Bytes))
        print("Flow started at system boot +" + str(self.flowStart / 1000) + " seconds")
        print("Flow last observed at system boot +" + str(self.flowEnd / 1000) + " seconds")
        print("Flow has been alive for " + str((self.flowEnd / 1000) - (self.flowStart / 1000)) + " seconds")
        print("UDP/TCP Source Port: " + utils.translateWellKnownPort(self.srcPort))
        print("UDP/TCP Destination Port: " + utils.translateWellKnownPort(self.dstPort))
        print("Cumulative TCP Flags: " + utils.expandTCPFlags(self.tcpFlags))
        print("IP Protocol Type: " + utils.getIPType(self.ipProt))
        print("Type of Service: " + str(self.tos))
        print("Source Autonomous System Number: " + str(self.srcAS))
        print("Destination Autonomous System Number: " + str(self.dstAS))
        print("Source Netmask: /" + str(self.srcMask))
        print("Destination Netmask: /" + str(self.dstMask))