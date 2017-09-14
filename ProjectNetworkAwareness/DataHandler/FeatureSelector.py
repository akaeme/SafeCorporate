from pymongo import MongoClient, ASCENDING
import sys, argparse
from progressbar import *
from Packet import Packet
from TimeFrame import TimeFrame
from datetime import datetime
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# initialization of the dict that will only contain 1 item at time
data = {}
# max size of buffer
SIZE = 5000
# buffer that can have 5000 packets
buffer = []
# Time Windows 5 or 120 seconds
TIMEWINDOW = None
# timestamp variable to control timewindow
firstTimestamp = 0

def packetIterator():
    client = MongoClient('mongodb://localhost:27017/')
    databases = ['UserProfiling', 'Anomalies']
    #db = client['UserProfiling']
    for database in databases:
        logger.info('Processing data on database %s', database)
        db = client[database]
        db_ = client['Clear'+database]
        collectionName = 'Samples'
        mapping = {'Monday': 0,
                   'Tuesday': 1,
                   'Wednesday': 2,
                   'Thursday': 3,
                   'Friday': 4}
        collections = db.collection_names()
        ordered = [None for n in range(5)]
        for day in collections:
            ordered[mapping[day]] = day
        # print(ordered)
        packetTotal = sum([db.get_collection(x).count() for x in collections])
        logger.info('Number of packets on database: %s', packetTotal)
        # print(packetTotal)
        count = 0
        bar = ProgressBar(widgets=['Progress: ', Percentage(), ' ', Bar(marker='#', left='[', right=']'),
                                   ' ', ETA(), ' ', FileTransferSpeed()], maxval=packetTotal)
        bar.start()
        for collection in ordered:
            # print(collection)
            collection_ = db.get_collection(collection)
            cursor = collection_.find({})  # get all documents
            for doc in cursor:
                selectFeatures(doc)
                if len(buffer) == SIZE:
                    # logger.info('Writing 5000 packet....')
                    for i in range(len(buffer)):
                        count += 1
                        bar.update(count)
                        try:
                            op = db_[collectionName].insert(buffer[i], check_keys=False)
                        except:
                            print('Ups, something went wrong.')
                            exit()
                    del buffer[:]
            for i in range(len(buffer)):
                count += 1
                bar.update(count)
                try:
                    op = db_[collectionName].insert(buffer[i], check_keys=False)
                except:
                    print('Ups, something went wrong.')
                    exit()
            del buffer[:]
        bar.finish()


    '''db = client['Anomalies']
    #db_ = client['ClearData']
    db_ = client['ClearDataAnomalies']
    mapping = {'Monday': 0,
           'Tuesday': 1,
           'Wednesday': 2,
           'Thursday': 3,
           'Friday': 4}
    collections = db.collection_names()
    ordered = [None for n in range(5)]
    for day in collections:
        ordered[mapping[day]]= day
    #print(ordered)
    packetTotal = sum([db.get_collection(x).count() for x in collections])
    print(packetTotal)
    count = 0
    bar = ProgressBar(widgets=['Progress: ', Percentage(), ' ', Bar(marker='#', left='[', right=']'),
                               ' ', ETA(), ' ', FileTransferSpeed()], maxval=packetTotal)
    bar.start()
    for collection in ordered:
        #print(collection)
        collection_ = db.get_collection(collection)
        cursor = collection_.find({})   # get all documents
        for doc in cursor:
            selectFeatures(doc)
            if len(buffer) == SIZE:
                #logger.info('Writing 5000 packet....')
                for i in range(len(buffer)):
                    count += 1
                    bar.update(count)
                    try:
                        op = db_[collectionName].insert(buffer[i], check_keys=False)
                    except:
                        print('Ups, something went wrong.')
                        exit()
                del buffer[:]
        for i in range(len(buffer)):
            count += 1
            bar.update(count)
            try:
                op = db_[collectionName].insert(buffer[i], check_keys=False)
            except:
                print('Ups, something went wrong.')
                exit()
        del buffer[:]
    bar.finish()'''

def selectFeatures(doc):
    # filter to dump only tcp packets
    #print(int(doc['body'][0]['ipProt'][2:], 2))
    if int(doc['body'][0]['ipProt'][2:], 2) == 6:
        packet = Packet(int(doc['body'][0]['srcIP'][2:],2), doc)
        buffer.append(packet.__dict__())

def analyseTimeFrame(data):
    # To change global variable
    global firstTimestamp
    # added the division in order to revert to float from int
    epoch_ms = float(data['epoch'])
    # print(epoch_ms)
    if firstTimestamp == 0:
        firstTimestamp = epoch_ms
        return False
    else:
        if epoch_ms - firstTimestamp >= TIMEWINDOW:
            firstTimestamp = 0
            return True
        else:
            return False

def processFeatures(database, classification):
    client = MongoClient('mongodb://localhost:27017/')
    #db_ = client['ClearData']
    #db_ = client['TestSamplesNormal']
    db_ = client[database]
    #collection = db_['Data']
    collection = db_['Samples']
    mapping = {5:'TimeFrame5S',
               120:'TimeFrame2M'}
    collectionName = mapping[TIMEWINDOW]
    cursor = collection.find({}, {'_id': False})
    collector = TimeFrame(TIMEWINDOW)
    print(collection.count())
    count = 0
    bar = ProgressBar(widgets=['Progress: ', Percentage(), ' ', Bar(marker='#', left='[', right=']'),
                               ' ', ETA(), ' ', FileTransferSpeed()], maxval=collection.count())
    bar.start()
    for i in cursor:
        count += 1
        bar.update(count)
        collector.add(i)
        if analyseTimeFrame(i):
            if TIMEWINDOW == 5:
                data = collector.getFeaturesSmallTimeWindow(i, classification)
            else:
                data = collector.getFeaturesBigTimeWindow(i, classification)
            collector = TimeFrame(TIMEWINDOW)
            try:
                op = db_[collectionName].insert(data, check_keys=False)
            except:
                print('Ups, something went wrong.')
                exit()
            # clear tmp dict, data already in db
            data.clear()
    bar.finish()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Feature Selector. First get the data from UserProfiling/Anomalies and then dump all features')
    parser.add_argument('-c', action="store_true", dest='collection',
                        help='Collection name to save clear data.')
    parser.add_argument('-t', action="store", dest='timeWindow', type=int,
                        help='Time window to calculate some features (ie: 5, 120 seconds).')
    parser.add_argument('-l', action="store", dest='classification',
                        help='Classify traffic mapped on features selected. Normal traffic should be 0 and anormal 1.')
    parser.add_argument('-d', action="store", dest='database',
                        help='Database to get samples and produce features mapped in time.')
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = vars(args)

    if args['timeWindow'] is not None:
        TIMEWINDOW = args['timeWindow']
        processFeatures(args['database'], args['classification'])
    elif args['collection']:
        packetIterator()
