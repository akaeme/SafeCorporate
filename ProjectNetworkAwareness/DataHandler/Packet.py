from netaddr import IPAddress
from datetime import datetime
getWeekDay  = lambda x : datetime.fromtimestamp(x).strftime("%A")
getHours    = lambda x : int(datetime.fromtimestamp(x).strftime('%H'))
getMinutes  = lambda x : int(datetime.fromtimestamp(x).strftime('%M'))
getSeconds  = lambda x : float(datetime.fromtimestamp(x).strftime('%S.%f'))
class Packet(object):
    # Only tcp packet will be considered ipProt must be 6
    srcIP = None
    dstIP = None
    weekday = None
    hour = None
    minutes = None
    seconds = None
    bytes = None
    numberPackets = None
    srcPort = None
    dstPort = None
    synFlag = None
    rstFlag = None
    finFlag = None
    epoch = None
    def __init__(self, srcIP, netflow):
        super(Packet, self).__init__()
        self.srcIP = str(IPAddress(srcIP))
        self.fillFields(netflow)

    def fillFields(self, netflow):
        self.dstIP = str(IPAddress(int(netflow['body'][0]['dstIP'][2:], 2)))
        self.weekday = getWeekDay(int(netflow['header']['epoch_ms'][2:], 2)/1000)
        self.hour = getHours(int(netflow['header']['epoch_ms'][2:], 2)/1000)
        self.minutes = getMinutes(int(netflow['header']['epoch_ms'][2:], 2)/1000)
        self.seconds = getSeconds(int(netflow['header']['epoch_ms'][2:], 2)/1000)
        self.bytes = int(netflow['body'][0]['L3Bytes'][2:], 2)
        # is always 1
        self.numberPackets = int(netflow['body'][0]['numPkts'][2:], 2)
        self.srcPort = int(netflow['body'][0]['scrPort'][2:], 2)
        self.dstPort = int(netflow['body'][0]['dstPort'][2:], 2)
        self.synFlag = 1 if int(netflow['body'][0]['tcpFlags'][2:],2) & 0b10 == 0b10 else 0
        self.rstFlag = 1 if int(netflow['body'][0]['tcpFlags'][2:],2) & 0b100 == 0b100 else 0
        self.finFlag = 1 if int(netflow['body'][0]['tcpFlags'][2:],2) & 0b1 == 0b1 else 0
        self.epoch = float(int(netflow['header']['epoch_ms'][2:], 2)/1000)
    def __dict__(self):
        return {'srcIP'         : self.srcIP,
                'dstIP'         : self.dstIP,
                'weekday'       : self.weekday,
                'hours'         : self.hour,
                'minutes'       : self.minutes,
                'seconds'       : self.seconds,
                'bytes'         : self.bytes,
                'numberPackets' : self.numberPackets,
                'srcPort'       : self.srcPort,
                'dstPort'       : self.dstPort,
                'synFlag'       : self.synFlag,
                'rstFlag'       : self.rstFlag,
                'finFlag'       : self.finFlag,
                'epoch'         : self.epoch}








