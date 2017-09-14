from pymongo import MongoClient
from netaddr import *
import sys,os, argparse
from progressbar import *
from statistics import variance, mean
sys.path.insert(0, os.path.abspath('..'))
from  Utils.Constants import Constants
from  Utils.Utils import Utils
from GeoIP import GeoIP
client = MongoClient('mongodb://localhost:27017/')
db = client['UserProfiling']
collections = db.collection_names()
db_ = client['Statistics']
constants_ = Constants()
utils_ = Utils()

# initialization of the dict that will only contain 1 item at time
dataToDump = {}

removeTrash = lambda d: { k:v for k, v in d.items() if v != 0}

# for small window
outPkts = {} # Key destination ip - value pkts count
inPkts = {}
bytesCount = {}
tcpPkts = {}
tcpSyns = {}
tcpFins = {} #initialization
tcpAcks = {}
geoip = {}  #initialization
deltatime = {}
# 0 legit 1 attack
CLASSIFICATION = None

#for big window
groupPackets = []
groupTcp = []
groupBytesPerPacket = []
groupSyn = []
groupFin = []
groupAck = []
groupOut = []
groupIn = []
groupAngles = []
groupDeltas = []
classification = []
# Used port to communicate to outside of the enterprise network
#{'200.200.0.1': {'srcPort': ['dstport']}
ports = {}

# Time Windows 5 or 120 seconds
TIMEWINDOW = None
firstTimestamp = 0

def iterateDocs(collectionName):
    packetCount = 0
    counterkeys = 0
    for collection in collections:
        collection_ = db.get_collection(collection)
        cursor = collection_.find({})   # get all documents
        for doc in cursor:
            analyse(doc, packetCount)
            packetCount += 1
            if incrementCounter(doc):
                #print(packetCount)
                updateDictionariesSmallWindow(packetCount, counterkeys)
                packetCount = 0
                #print(dataToDump)
                try:
                    op = db_[collectionName].insert(dataToDump, check_keys=False)
                except:
                    print('Ups, something went wrong.')
                    exit()
                # clear tmp dict, data already in db
                dataToDump.clear()
                counterkeys += 1
        #for key, val in tcpSyns.items():
            #print(key + ' ' + str(val-tcpFins[key]))
        #print(numPkts)
        #print(bytesCount)

def incrementCounter(data):
    # To change global variable
    global firstTimestamp
    # added the division in order to revert to float from int
    epoch_ms = float(int(data['header']['epoch_ms'][2:], 2)/1000)
    #print(epoch_ms)
    if firstTimestamp == 0:
        firstTimestamp = epoch_ms
        return False
    else:
        if epoch_ms - firstTimestamp >= TIMEWINDOW:
            firstTimestamp = 0
            return True
        else:
            return False

def processDeltas(deltas):
    for k,v in deltas.items():
        deltas[k]=mean([j - i for i, j in zip(v[:-1], v[1:])])
    return deltas
#
def iterateDocs_(collectionName):
    recordsCount = 0
    counterkeys = 0
    collection_ = db_.get_collection('TimeFrameFive')
    cursor = collection_.find({},{'_id': False})  # get all documents
    bar = ProgressBar(widgets=['Progress: ', Percentage(), ' ', Bar(marker='#', left='[', right=']'),
                               ' ', ETA(), ' ', FileTransferSpeed()], maxval=collection_.count())
    bar.start()
    iterDocs = 0
    for doc in cursor:
        bar.update(iterDocs)
        analyseDoc(doc[str(iterDocs)], recordsCount)
        iterDocs += 1
        recordsCount += 1
        # 120 / 5 = 24, we must process 24 records
        if recordsCount == 24:
            # print(packetCount)
            updateDictionariesBigWindow(recordsCount,counterkeys)
            recordsCount = 0
            # print(dataToDump)
            try:
                op = db_[collectionName].insert(dataToDump, check_keys=False)
            except:
                print('Ups, something went wrong.')
                exit()
            dataToDump.clear()
            counterkeys += 1
    bar.finish()

def updateDictionariesBigWindow(recordsCount, key):
    meanPackets = mean(groupPackets)
    meanTcp = mean(groupTcp)
    meanBytesPerPacket = mean(groupBytesPerPacket)
    meanSyn = mean(groupSyn)
    meanFin = mean(groupFin)
    meanAck = mean(groupAck)
    meanOut = mean(groupOut)
    meanIn = mean(groupIn)
    meanAngles = mean(groupAngles)
    meanDeltas = mean(groupDeltas)
    # it should be 0 or 1
    meanClass = mean(classification)

    dataToDump[str(key)] ={'meanPackets':  meanPackets,
                           'meanTcp': meanTcp,
                           'meanBytesPerPacket': meanBytesPerPacket,
                           'meanSyn': meanSyn,
                           'meanFin': meanFin,
                           'meanAck': meanAck,
                           'meanOut': meanOut,
                           'meanIn': meanIn,
                           'meanAngles': meanAngles,
                           'meanDeltas': meanDeltas,
                           'meanClass': meanClass
                           }

    # clear lists
    del groupPackets[:]
    del groupTcp[:]
    del groupBytesPerPacket[:]
    del groupSyn[:]
    del groupFin[:]
    del groupAck[:]
    del groupOut[:]
    del groupIn[:]
    del groupAngles[:]
    del groupDeltas[:]
    del classification[:]

'''
    # __doc__
    # meanTcp       - mean tcp packets sent
    # meanSyn       - mean tcp syn packets sent
    # meanBytesPerPacket    - mean bytes
    # meanOut       - mean out packets
    # meanIn        - mean in packets
    dataToDump[str(key)] = {'packetNumber': packetNumber,  #total number
                        'sumBytes': sumBytes,
                        'tcpNumber': tcpNumber,
                        'tcpSynNumber': tcpSynNumber,
                        'tcpFinNumber': tcpFinNumber,
                        'tcpAckNumber': tcpAckNumber,
                        'toOutsidePkts': sumOut,  #packet to dst
                        'toInsidePkts': sumIn,
                        'anglesVariance': anglesVariance,
                        'deltatime': deltas,
                        'classification': CLASSIFICATION,
                        # 'ports': ports.copy(),
                        # 'bytesCount': removeTrash(bytesCount).copy(),
                        # 'tcpPkts': tcpPktsClean.copy(),
                        # 'tcpSyns': tcpSynsClean.copy(),
                        # 'tcpFins': removeTrash(tcpFins).copy(),
                        # 'geoIP': geoip.copy(),
                        'meanTcp': meanTcp,
                        'meanSyn': meanSyn,
                        'meanBytesPerPacket': meanBytesPerPacket,
                        'meanOut': meanOut,
                        'meanIn': meanIn,
                        'meanDeltas':
                            }
'''
#
def updateDictionariesSmallWindow(packetNumber, key):
    tcpPktsClean = removeTrash(tcpPkts)
    tcpSynsClean = removeTrash(tcpSyns)
    tcpFinsClean = removeTrash(tcpFins)
    tcpAcksClean = removeTrash(tcpAcks)
    tcpNumber = sum(tcpPktsClean.values())
    tcpSynNumber = sum(tcpSynsClean.values())
    tcpFinNumber = sum(tcpFinsClean.values())
    tcpAckNumber = sum(tcpAcksClean.values())
    sumBytes = sum(bytesCount.values())
    sumOut = sum(outPkts.values())
    sumIn = sum(inPkts.values())
    angles = [a['angle'] for a in list(geoip.values())]

    distances = [a['distance'] for a in list(geoip.values())]
    anglesMean = mean(angles) if len(angles) > 0 else 0
    distanceMean = mean(distances) if len(distances) > 0 else 0
    deltas = dict([(k,v) for k, v in deltatime.items() if len(v)>1])
    deltas = mean(processDeltas(deltas).values()) if len(deltas) > 0 else 0

    # __doc__
    # packetNumber  - total number of packets (in and out)
    # sumBytes      - sum of all bytes sent
    # tcpNumber     - number of tcp packets sent
    # tcpSynNumber  - number of syn flags sent
    # tcpFinNumber  - number of fin flags sent
    # tcpAcksNumber - number of ack flags sent
    # toOutsidePkts - number of packets sent
    # toInsidePkts  - number of packets received
    # anglesVariance- angles variance
    # deltatime     - mean time between consecutive packets
    # classification- classification of the traffic

    # ports         - ports used
    # bytesCount    - dictionary containing bytes sent to respective key
    # tcpPkts       - dictionary containing tcp packets sent to respective key
    # tcpSyns       - dictionary containing tcp syns sent to respective key
    # tcpFins       - dictionary containing tcp fins sent to respective key
    # geoIP         - dictionary containing the ip geo of respective key
    dataToDump[str(key)] = {'packetNumber': packetNumber,
                        'sumBytes': sumBytes,
                        'tcpNumber': tcpNumber,
                        'tcpSynNumber': tcpSynNumber,
                        'tcpFinNumber': tcpFinNumber,
                        'tcpAckNumber': tcpAckNumber,
                        'toOutsidePkts': sumOut,
                        'toInsidePkts': sumIn,
                        'anglesVariance': anglesMean,
                        'distance': distanceMean,
                        'deltatime': deltas,
                        'classification': CLASSIFICATION,
                            }
    outPkts.clear()
    bytesCount.clear()
    tcpPkts.clear()
    tcpSyns.clear()
    tcpFins.clear()
    tcpAcks.clear()
    geoip.clear()
    ports.clear()
    deltatime.clear()

# and multicast 2
def checkNonPrivateIP(ip):
    ip = IPAddress(ip)
    privateNetworks = list(constants_.ipClassesPrivate.keys())+list(constants_.ipClasses.keys())
    for network in privateNetworks:
        if ip in network:
            return False
    #print(str(ip) + ' passed!')
    return True

def analyse(data, packetCount):
    srcIP = str(IPAddress(int(data['body'][0]['srcIP'][2:],2)))
    dstIP = str(IPAddress(int(data['body'][0]['dstIP'][2:],2)))

    # Only traffic from inside to outside
    if IPAddress(srcIP) in IPNetwork(constants_.ENTERPRISE_SUBNET):
        if checkNonPrivateIP(dstIP):
            try:
                geoip[packetCount] = GeoIP(dstIP).__dict__()
            except:
                print(str(dstIP) + ' was bugged')
                pass
        keys = outPkts.keys()
        if dstIP not in list(keys):
            outPkts[dstIP] = int(data['body'][0]['numPkts'][2:], 2)
            bytesCount[dstIP] = int(data['body'][0]['L3Bytes'][2:], 2)
            srcPort = str(int(data['body'][0]['scrPort'][2:], 2))
            dstPort = str(int(data['body'][0]['dstPort'][2:], 2))
            ports[dstIP] = {srcPort:[dstPort]}
            tcpPkts[dstIP] = 0
            tcpSyns[dstIP] = 0
            tcpFins[dstIP] = 0
            tcpAcks[dstIP] = 0
            deltatime[dstIP] = [float(int(data['header']['epoch_ms'][2:], 2)/1000)]
            #if int(data['body'][0]['tcpFlags'][2:], 2) != 0:
            if int(data['body'][0]['ipProt'][2:], 2) == 6:
                tcpPkts[dstIP] = 1
                #print(int(data['body'][0]['tcpFlags'][2:],2))
                # At least 1 syn flag
                if int(data['body'][0]['tcpFlags'][2:],2) & 0b10 == 0b10:
                    tcpSyns[dstIP] = 1
                # At least 1 fin flag
                if int(data['body'][0]['tcpFlags'][2:],2) & 0b1 == 0b1 or int(data['body'][0]['tcpFlags'][2:],2) & 0b100 == 0b100:
                    tcpFins[dstIP] = 1
                # At least 1 ack flag
                if int(data['body'][0]['tcpFlags'][2:], 2) & 0b10000 == 0b10000:
                    tcpAcks[dstIP] = 1
        else:
            outPkts[dstIP] += int(data['body'][0]['numPkts'][2:], 2)
            bytesCount[dstIP] += int(data['body'][0]['L3Bytes'][2:], 2)
            srcPort = str(int(data['body'][0]['scrPort'][2:], 2))
            dstPort = str(int(data['body'][0]['dstPort'][2:], 2))
            deltatime[dstIP].append(float(int(data['header']['epoch_ms'][2:], 2) / 1000))
            if srcPort in list(ports[dstIP].keys()):
                if dstPort not in ports[dstIP][srcPort]:
                    ports[dstIP][srcPort].append(dstPort)
            else:
                ports[dstIP][srcPort] = [dstPort]

            # if int(data['body'][0]['tcpFlags'][2:], 2) != 0:
            if int(data['body'][0]['ipProt'][2:], 2) == 6:
                tcpPkts[dstIP] += 1
                # At least 1 syn flag
                #print(int(data['body'][0]['tcpFlags'][2:], 2))
                if int(data['body'][0]['tcpFlags'][2:],2) & 0b10 == 0b10:
                    tcpSyns[dstIP] += 1
                # At least 1 fin flag
                if int(data['body'][0]['tcpFlags'][2:],2) & 0b1 == 0b1 or int(data['body'][0]['tcpFlags'][2:],2) & 0b100 == 0b100:
                    tcpFins[dstIP] += 1
                # At least 1 ack flag
                if int(data['body'][0]['tcpFlags'][2:], 2) & 0b10000 == 0b10000:
                    tcpAcks[dstIP] += 1

    # Traffic outside to inside
    elif IPAddress(dstIP) in IPNetwork(constants_.ENTERPRISE_SUBNET):
        keys = inPkts.keys()
        if srcIP not in list(keys):
            inPkts[srcIP] = int(data['body'][0]['numPkts'][2:], 2)
        else:
            inPkts[srcIP] += int(data['body'][0]['numPkts'][2:], 2)

def analyseDoc(doc, recordsCount):
    groupPackets.append(doc['packetNumber'])
    groupTcp.append(doc['tcpNumber'])
    groupBytesPerPacket.append(doc['sumBytes'])
    groupSyn.append(doc['tcpSynNumber'])
    groupFin.append(doc['tcpFinNumber'])
    groupAck.append(doc['tcpAckNumber'])
    groupOut.append(doc['toOutsidePkts'])
    groupIn.append(doc['toInsidePkts'])
    groupAngles.append(doc['anglesVariance'])
    groupDeltas.append(doc['deltatime'])
    classification.append(int(doc['classification']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Feature generator according to the context of the project')
    parser.add_argument('-t', action="store", dest='timeWindow',type=int,
                        help='Time window to calculate some features (only support \'5\' and \'120\' seconds).')
    parser.add_argument('-c', action="store", dest='collectionName',
                        help='Collection name to save the calculated features.')
    parser.add_argument('-l', action="store", dest='classification',
                        help='Classify traffic mapped on features selected.')
    args = parser.parse_args()
    if len(sys.argv) == 1 or len(sys.argv) < 4:
        parser.print_help()
        sys.exit(1)
    args = vars(args)
    if not (args['timeWindow'] == 5 or args['timeWindow'] == 120):
        parser.print_help()
        sys.exit(1)
    TIMEWINDOW = args['timeWindow']
    CLASSIFICATION = args['classification']
    if TIMEWINDOW == 5:
        iterateDocs(args['collectionName'])
    else:
        iterateDocs_(args['collectionName'])
