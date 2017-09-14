import logging
import argparse
import sys, os
from datetime import datetime
from progressbar import *
from struct import pack_into
from array import array
from netaddr import *
sys.path.insert(0, os.path.abspath('..'))
from  Utils.Constants import Constants
from Utils.Utils import Utils
constants = Constants()
utils_ = Utils()

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
from scapy.all import *

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
lifo = queue.LifoQueue()
buffer = []
bufferNetflow = []
bufferTimeStamps = []
filenameNetflow = ''

getSeconds = lambda x : float(datetime.fromtimestamp(x).strftime('%S.%f'))

def sniffer(net_iface, pkt_to_sniff, time_to_sniff):
    subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)
    logger.debug('Interface ' + net_iface + ' was set to PROMISC mode.')    #every transaction passes though cpu
    file_name = input("Please give a name to the log file: ")
    packet_number = 0
    # Running the sniffing process
    pkt = sniff(iface=net_iface, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=processPacket)


    # Opening the file
    sniffer_log = open(file_name, "wb")
    while not lifo.empty():
        pickle.dump(lifo.get(), sniffer_log)
    # Closing the log file
    sniffer_log.close()

    # Opening the file to store timestamp of each packet
    idx = file_name.index('.txt')
    fname = file_name[:idx] + '_timestamps' + file_name[idx:]
    timestamp_log = open(fname, "w")
    for ts in bufferTimeStamps:
        timestamp_log.write('%s\n' % ts)
    # Closing the log file
    timestamp_log.close()

def processPacket(packet):
    lifo.put(PickablePacket(packet))
    bufferTimeStamps.append(packet.time)

class PickablePacket:
    # A wrapper for scapy packets that can be pickled.
    def __init__(self, pkt):
        self.contents = bytes(pkt)

    def __call__(self):
        # Get the original scapy packet.
        pkt = Ether(self.contents)
        return pkt

def loadFromFile():
    global bufferTimeStamps
    filename = input('Filename : ')
    idx = filename.index('.txt')
    fname = filename[:idx] + '_timestamps' + filename[idx:]
    try:
        sniffer_log = open(os.getcwd() + '/../Data/' + filename, 'rb')
    except IOError:
        print('Error: File does not exist.')
        exit()
    else:
        while True:
            try:
                buffer.append(pickle.load(sniffer_log))
            except EOFError:
                break
        sniffer_log.close()
    try:
        timestamp_log = open(os.getcwd() + '/../Data/' + fname, 'r')
    except IOError:
        print('Error: File does not exist.')
        exit()
    else:
        try:
            bufferTimeStamps = timestamp_log.readlines()
        except EOFError:
            print('Error reading timestamps file.')
        bufferTimeStamps = [float(x) for x in bufferTimeStamps]
        timestamp_log.close()


def buildIPv4(pkt):
    #ether = {field_name: getattr(pkt[0], field_name) for field_name in constants.Ether_Fields}
    ip = {field_name: getattr(pkt[1], field_name) for field_name in constants.IP_Fields}
    if ip['proto'] == 6:    #TCP
        #1091
        tcp = {field_name: getattr(pkt[2], field_name) for field_name in constants.TCP_Fields}
        srcMask = utils_.checkClassAndGetMask(ip['src'])
        dstMask = utils_.checkClassAndGetMask(ip['dst'])
        return ip['src'], ip['dst'], ip['len']-20, tcp['sport'], tcp['dport'], tcp['flags'], ip['proto'], ip['tos'], srcMask, dstMask
    elif ip['proto'] == 17: #UDP
        #91
        udp = {field_name: getattr(pkt[2], field_name) for field_name in constants.UDP_Fields}
        srcMask = utils_.checkClassAndGetMask(ip['src'])
        dstMask = utils_.checkClassAndGetMask(ip['dst'])
        return ip['src'], ip['dst'], ip['len'] - 20, udp['sport'], udp['dport'], 0, ip['proto'], ip['tos'], srcMask, dstMask
    else:
        srcMask = utils_.checkClassAndGetMask(ip['src'])
        dstMask = utils_.checkClassAndGetMask(ip['dst'])
        return ip['src'], ip['dst'], ip['len'] - 20, 0,0, 0, ip['proto'], ip['tos'], srcMask, dstMask

def buildARP(pkt):
    #3980
    arp = {field_name: getattr(pkt[1], field_name) for field_name in constants.ARP_Fields}
    srcMask = utils_.checkClassAndGetMask(arp['psrc'])
    dstMask = utils_.checkClassAndGetMask(arp['pdst'])
    return arp['psrc'], arp['pdst'], 28 , 0, 0, 0, 0x04, 0, srcMask, dstMask

def buildPacket(values, timestamp, index=None):
    #Build Packet
    version = 5 #Netflowv5
    num_flows = 1   #1 flow per packet
    uptime = 0
    epoch_ms = int(timestamp*1000)
    epoch_ns = 0
    total_flows = 0
    engine_type = 0
    engine_id = 0
    sample_rate = 0
    pktPayload = array.array('B', (28 + (num_flows * 48)) * b"\0")
    #print(epoch_ms)
    pack_into(constants.NETF_V5H_CHANGED, pktPayload, 0, version, num_flows, uptime, epoch_ms, epoch_ns, total_flows,
              engine_type, engine_id, sample_rate)

    # it was 24 but i changed in order to have space for timestamp epoch with milis
    offset = 28

    srcIP = int(IPAddress(values[0]))
    dstIP = int(IPAddress(values[1]))
    nextHop = int(IPAddress('0.0.0.0'))  # doesn't matter
    snmpIn = 1
    snmpOut = 2
    numPkts = 1
    L3Bytes = values[2]
    flowStart = 0
    flowEnd = 0
    srcPort = values[3]
    dstPort = values[4]
    tcpFlags = values[5]
    ipProt = values[6]
    tos = values[7]
    srcAS = 0
    dstAS = 1
    srcMask = int(values[8])
    dstMask = int(values[9])

    pack_into(constants.NETF_V5B, pktPayload, offset, srcIP, dstIP, nextHop,
              snmpIn, snmpOut, numPkts, L3Bytes, flowStart, flowEnd, srcPort, dstPort, 0, tcpFlags, ipProt,
              tos, srcAS, dstAS, srcMask, dstMask, 0)
    # offset += 48   it has only 1 flows
    #logger.info(str(index) + ' ' + str(len(pktPayload)))
    bufferNetflow.append(pktPayload)

def buildPackets(INITIAL_EPOCH):
    switch = {0x800: buildIPv4,
              0x806: buildARP}
    assert (buffer[0]()[0].type != 0x86dd and buffer[0]()[0].type != 0x888e)
    initialUnixTimeStamp = bufferTimeStamps[0]

    numberOfPackets = len(buffer)

    bar = ProgressBar(widgets=['Progress: ', Percentage(), ' ', Bar(marker='#', left='[', right=']'),
                                ' ', ETA(), ' ', FileTransferSpeed()], maxval=numberOfPackets)
    bar.start()
    for i in range(numberOfPackets):
        #   #1742
        if buffer[i]()[0].type == 0x86dd or buffer[i]()[0].type == 0x888e:
            continue
        #if buffer[i]()[0].type == 0x806:
        #print(str(i))
        try:
            values = list(switch[buffer[i]()[0].type](buffer[i]()))
        except:
            print(str(i) + ' Error, protocol not implemented. Go debug!')
        else:
            diff = bufferTimeStamps[i] - initialUnixTimeStamp
            if i == 0:
                timestamp = INITIAL_EPOCH + getSeconds(initialUnixTimeStamp) - int(getSeconds(initialUnixTimeStamp))
            else:
                timestamp = INITIAL_EPOCH + diff
            buildPacket(values, round(timestamp,4), i)
            bar.update(i)
    bar.finish()

    filenameNetflow = input('Filename to save netflow records: ')
    fileName = open(os.getcwd() + '/../Data/' + filenameNetflow, "wb")
    bar = ProgressBar(widgets=['Progress: ', Percentage(), ' ', Bar(marker='*', left='[', right=']'),
                               ' ', ETA(), ' ', FileTransferSpeed()], maxval=len(bufferNetflow))
    bar.start()
    for nt in bufferNetflow:
        fileName.write(nt)
        if bufferNetflow.index(nt) != len(bufferNetflow) - 1:
            fileName.write(b'\n\n')
        bar.update(bufferNetflow.index(nt))
    fileName.close()
    bar.finish()

if __name__ == '__main__':
    if os.geteuid() == 0:
        logger.info('Program is running as root!')
    else:
        logger.critical("You need to run this program as root for it to function correctly.")
        sys.exit(1)

    INITIAL_EPOCH = int(time.mktime(time.strptime('21.05.2017 10:10:00.00', '%d.%m.%Y %H:%M:%S.%f')))

    parser = argparse.ArgumentParser(
        description='Scapy sniffer to collect traffic in order to build netflow packets. ')
    parser.add_argument('-i', action="store", dest='net_iface', help='The interface on which to run the sniffer (like \'eth0\').')
    parser.add_argument('-p', action="store", dest='pkt_to_sniff', help='The number of packets to capture (0 is infinity).')
    parser.add_argument('-s', action="store", dest='time_to_sniff', help='The time interval to sniff (in seconds).')
    parser.add_argument('-r', action="store", dest='read', help='Produce Netflow records from traffic on a file.')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = vars(args)
    if args['read']:
        loadFromFile()
        buildPackets(INITIAL_EPOCH)
        sys.exit(0)
    for key, val in args.items():
        if val is None and key !='read':
            logger.debug('You must specify ' + key)
            sys.exit(1)

    sniffer(args['net_iface'], args['pkt_to_sniff'], args['time_to_sniff'])

'''
########################IP HEADER ###############################
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

########################TCP HEADER ##############################
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

'''

