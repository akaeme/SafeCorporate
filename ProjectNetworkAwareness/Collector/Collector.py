import socket, logging

MAX_FLOWS = 100

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Collector(object):
    def __init__(self, host="0.0.0.0", port=9996):
        super(Collector, self).__init__()
        self.host = host
        self.port = port
        self.listener = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #UDP
        self.listener.bind((host, port))
        self.buffer = None
        self.queue = []

    def collectNetFlowPackets(self):
        if self.getData():
            logging.info('Flow received.')
            self.queue[len(self.queue):] = [self.buffer]        #append to queue
            logging.warning('Queue size: ' + str(len(self.queue)))
            self.buffer = ''
            if len(self.queue) > MAX_FLOWS:
                self.saveData()

    def getData(self):
        data, addr = self.listener.recvfrom(8192)  # buffer size is 8192 bytes
        self.buffer = data
        return self.buffer != ''

    def saveData(self):
        filename = input('File name: ')
        file = open(filename, 'wb')
        logging.info('Writing raw packets!')
        for flow in self.queue:
            file.write(flow)
            if self.queue.index(flow) != len(self.queue) - 1:
                file.write(b'\n\n')
        file.close()
        self.queue = []
        logging.info('Empty Queue.')

    def cleanUp(self):
        self.listener.close()

if __name__ == "__main__":
    flowCollector = Collector()
    logging.info('Listening on ' + flowCollector.host + ' : ' + str(flowCollector.port))
    try:
        while True:
            flowCollector.collectNetFlowPackets()
    except KeyboardInterrupt:
        if len(flowCollector.queue) > 0:
            logging.warning("Done!\nWriting raw packets to log!")
            flowCollector.saveData()
        else:
            logging.warning("Done!\nThere is no raw packets to log!")
        flowCollector.cleanUp()
        exit()
