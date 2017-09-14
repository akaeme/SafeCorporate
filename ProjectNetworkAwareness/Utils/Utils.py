from .Constants import Constants
from netaddr import IPNetwork, IPAddress


constants = Constants()
class Utils:
    #def int_to_ipv4(self, address):
        #return "%d.%d.%d.%d" % (address >> 24 & 0xff, address >> 16 & 0xff, address >> 8 & 0xff, address & 0xff)

    def translateWellKnownPort(self, portNum):
        try:
            protocolPort = constants.protocols_ports[portNum]
        except KeyError:
            protocolPort = str(portNum)
        return protocolPort

    def getIPType(self, typeNum):
        try:
            protocolName = constants.protocols_type[typeNum]
        except KeyError:
            protocolName = "Other (" + str(typeNum) + ")"
        return protocolName

    def getIPTypeHex(self, typeStr):
        # invert dictionary
        protocols = dict([(v.lower(), hex(k)) for k, v in constants.protocols_type.items()])
        try:
            protocolName = protocols[typeStr.lower()]
        except KeyError:
            protocolName = protocols['unknown']
        return int(protocolName, 16)

    def expandTCPFlags(self, flagSummary):
        flagsPresent = []
        bits = bin(flagSummary)[2:].zfill(8)

        for i in range(len(constants.tcp_flags)):
            if bits[i] == "1":
                flagsPresent.append(constants.tcp_flags[i])

        return " ".join(flagsPresent)

    def chooseTCPFlags(self):
        for i in range(len(constants.tcp_flags)):
            print('# {} {:<4} '.format(i, constants.tcp_flags[i]))
        flags = input('Choose Flags(\'flag\' space \'flag\') : ').split(' ')
        flags = list(map(int, flags))
        flags = [1 if i in flags else 0 for i in range(len(constants.tcp_flags))]
        flags = ''.join(str(e) for e in flags)
        return int(flags,2)    #binary

    def checkClassAndGetMask(self, ip):
        ip = IPAddress(ip)
        for key, value in constants.ipClassesPrivate.items():
            if ip in key:
                return value
        for key, value in constants.ipClasses.items():
            if ip in key:
                return value
        return '24'     #default




