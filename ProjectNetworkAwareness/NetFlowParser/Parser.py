import struct, sys, os
#sibling module
sys.path.insert(0, os.path.abspath('..'))
from  Utils.Constants import Constants
from Utils.Database import Database
#same directory
from Flow import Flow
from netaddr import *
constants = Constants()


class Parser(object):
    """docstring for Parser"""

    def __init__(self, data=None, db_name=None):
        super(Parser, self).__init__()
        self.buffer = data
        self.database = Database(db_name=db_name)
        #self.database.deleteAll()

    def parseNetFlowData(self, data=None, collection_name = None):
        if data is not None:
            self.buffer = data
        try:
            data = struct.unpack("!H", self.buffer[:2])
        except:
            print(data)
            return
        version = data[0]

        if version == 1:
            header_len = struct.calcsize(constants.NETF_V1H)

            if len(self.buffer) < header_len:
                print("Truncated packet (header)")
            header = struct.unpack(constants.NETF_V1H, self.buffer[:header_len])
            version = header[constants.VERSION]
            num_flows = header[constants.NUM_FLOWS]
            uptime = header[constants.UPTIME]
            epoch_ms = header[constants.EPOCH_MS]
            epoch_ns = header[constants.EPOCH_NS]

            flow = Flow(version, num_flows)                     #Flow object
            flow.setHeader(uptime, epoch_ms, epoch_ns)          #Set header

            body_len = struct.calcsize(constants.NETF_V1B)

            if len(self.buffer) - header_len != num_flows * body_len:
                print("Packet truncated (flows data)")
            for n in range(num_flows):
                offset = header_len + body_len * n
                body = struct.unpack(constants.NETF_V1B, self.buffer[offset:offset + body_len])
                srcIP = str(IPAddress(body[constants.SRC_IP]))
                dstIP = str(IPAddress(body[constants.DST_IP]))
                nextHop = str(IPAddress(body[constants.HOP_IP]))
                snmpIn = body[constants.IF_IN]
                snmpOut = body[constants.IF_OUT]
                numPkts = body[constants.NUM_PKTS]
                L3Bytes = body[constants.L3_BYTES]
                flowStart = body[constants.START]
                flowEnd = body[constants.END]
                srcPort = body[constants.SRC_PORT]
                dstPort = body[constants.DST_PORT]
                tcpFlags = body[constants.TCP_FLAGS]
                ipProt = body[constants.IP_PROT]
                tos = body[constants.SRV_TYPE]

                flow.setFlow(n, srcIP, dstIP, nextHop, snmpIn, snmpOut, numPkts, L3Bytes, flowStart, flowEnd, srcPort, dstPort, tcpFlags,
                             ipProt, tos)
        if version == 5:
            header_len = struct.calcsize(constants.NETF_V5H_CHANGED)

            if len(self.buffer) < header_len:
                print("Truncated packet (header)")

            # Changed header in order to have more than 4 bytes
            header = struct.unpack(constants.NETF_V5H_CHANGED, self.buffer[:header_len])

            version = header[constants.VERSION]
            num_flows = header[constants.NUM_FLOWS]
            uptime = header[constants.UPTIME]
            epoch_ms = header[constants.EPOCH_MS]
            epoch_ns = header[constants.EPOCH_NS]
            total_flows = header[constants.TOTAL_FLOWS]
            engine_type = header[constants.ENGINE_TYPE]
            engine_id = header[constants.ENGINE_ID]
            sample_rate = header[constants.SAMPLE_RATE]

            flow = Flow(version, num_flows)                 #Flow object
            flow.setHeader(uptime, epoch_ms, epoch_ns, total_flows, engine_type, engine_id, sample_rate)    #setHeader
            #flow.header.dumpHeader()
            body_len = struct.calcsize(constants.NETF_V5B)

            if len(self.buffer) - header_len != num_flows * body_len:
                print("Packet truncated (flows data)")
            for n in range(num_flows):
                offset = header_len + body_len * n
                body = struct.unpack(constants.NETF_V5B, self.buffer[offset:offset + body_len])
                srcIP = str(IPAddress(body[constants.SRC_IP]))
                dstIP = str(IPAddress(body[constants.DST_IP]))
                nextHop = str(IPAddress(body[constants.HOP_IP]))
                snmpIn = body[constants.IF_IN]
                snmpOut = body[constants.IF_OUT]
                numPkts = body[constants.NUM_PKTS]
                L3Bytes = body[constants.L3_BYTES]
                flowStart = body[constants.START]
                flowEnd = body[constants.END]
                srcPort = body[constants.SRC_PORT]
                dstPort = body[constants.DST_PORT]
                tcpFlags = body[constants.TCP_FLAGS]
                ipProt = body[constants.IP_PROT]
                tos = body[constants.SRV_TYPE]
                srcAS = body[constants.SRC_AS]
                dstAS = body[constants.DST_AS]
                srcMask = body[constants.SRC_MASK]
                dstMask = body[constants.DST_MASK]

                flow.setFlow(n, srcIP, dstIP, nextHop, snmpIn, snmpOut, numPkts, L3Bytes, flowStart, flowEnd, srcPort, dstPort, tcpFlags,
                             ipProt, tos, srcAS, dstAS, srcMask, dstMask)
                flow.classify(n)
                #flow.flows[n].dumpBody()    #print netflow
            #print(flow.__dict__())
            res = self.database.addData(collection_name=collection_name, data=flow.__dict__())

    def cleanUp(self):
        self.buffer = None