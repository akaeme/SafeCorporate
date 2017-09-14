from Header import Header
from Body import Body
from netaddr import *
from Utils import Constants
constants = Constants.Constants()

class Flow(object):
    def __init__(self, version, num_flows):
        super(Flow, self).__init__()
        self.version = version
        self.num_flows = num_flows
        self.header = Header(self.version)
        self.flows = [Body(self.version) for n in range(self.num_flows)]
        self.classification = [None for n in range(self.num_flows)]

    def setHeader(self, uptime, epoch_ms, epoch_ns, total_flows=None, engine_type=None, engine_id=None, sample_rate=None):
        if self.version == 1:
            self.header.setHeader(self.num_flows, uptime, epoch_ms, epoch_ns)
        elif self.version == 5:
            self.header.setHeader(self.num_flows, uptime, epoch_ms, epoch_ns, total_flows, engine_type, engine_id, sample_rate)
        else:
            print("Unsupported version.")

    def setFlow(self, index, srcIP, dstIP, nextHop, snmpIn, snmpOut, numPkts, L3Bytes, flowStart, flowEnd, srcPort, dstPort, tcpFlags=None, ipProt=None,
                tos=None, srcAS = None, dstAS = None, srcMask = None, dstMask = None):
        if self.version == 1:
            self.flows[index].setBody(srcIP, dstIP, nextHop, snmpIn, snmpOut, numPkts, L3Bytes, flowStart, flowEnd, srcPort, dstPort, tcpFlags, ipProt, tos)
        elif self.version == 5:
            self.flows[index].setBody(srcIP, dstIP, nextHop, snmpIn, snmpOut, numPkts, L3Bytes, flowStart, flowEnd,
                                      srcPort, dstPort, tcpFlags, ipProt, tos, srcAS, dstAS, srcMask, dstMask)
        else:
            print("Unsupported version.")

    def classify(self, index):
        if self.flows[index].srcNetwork in IPNetwork(constants.ENTERPRISE_SUBNET):
            self.classification[index] = constants.INSIDE
        else:
            self.classification[index] = constants.OUTSIDE

    def __dict__(self):
        #print({k:type(v) for k,v in self.flows[0].__dict__().items()})
        #print({k:type(v) for k,v in self.header.__dict__().items()})
        return {'header':self.header.__dict__(),
                'body': [fl.__dict__() for fl in self.flows]}


