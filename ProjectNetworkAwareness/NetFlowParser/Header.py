class Header(object):
    # Header
    num_flows = None
    uptime = None
    epoch_ms = None
    epoch_ns = None
    total_flows = None
    engine_type = None
    engine_id = None
    sample_rate = None
    def __init__(self, version):
        super(Header, self).__init__()
        self.version = version

    def __dict__(self):
        if self.version == 1:
            return {'num_flows' :   bin(self.num_flows),
                    'uptime'    :   bin(self.uptime),
                    'epoch_ms'  :   bin(self.epoch_ms),
                    'epoch_ns'  :   bin(self.epoch_ns)}
        else:
            return {'num_flows' :  bin(self.num_flows),
                'uptime'        :  bin(self.uptime),
                'epoch_ms'      :  bin(self.epoch_ms),
                'epoch_ns'      :  bin(self.epoch_ns),
                'total_flows'   :  bin(self.total_flows),
                'engine_type'   :  bin(self.engine_type),
                'engine_id'     :  bin(self.engine_id),
                'sample_rate'   :  bin(self.sample_rate)}

    def setHeader(self, num_flows, uptime, epoch_ms, epoch_ns, total_flows=None, engine_type=None, engine_id=None, sample_rate=None):
        if self.version == 1:
            self.num_flows = num_flows
            self.uptime = uptime
            self.epoch_ms = epoch_ms
            self.epoch_ns = epoch_ns
        elif self.version == 5:
            self.num_flows = num_flows
            self.uptime = uptime
            self.epoch_ms = epoch_ms
            self.epoch_ns = epoch_ns
            self.total_flows = total_flows
            self.engine_type = engine_type
            self.engine_id = engine_id
            self.sample_rate = sample_rate
        else:
            print("Version do not supported.")

    def dumpHeader(self):
        if self.version == 1:
            print("==== NetFlow Header Dump ====")
            print("NetFlow Version: " + str(self.version))
            print("Number of Flows in this Export: " + str(self.num_flows))
            print("System Uptime in Milliseconds: " + str(self.uptime))
            print("Time since Epoch in Milliseconds: " + str(self.epoch_ms))
            print("Residual Nanoseconds from Above: " + str(self.epoch_ns))
        elif self.version == 5:
            print("==== NetFlow Header Dump ====")
            print("NetFlow Version: " + str(self.version))
            print("Number of Flows in this Export: " + str(self.num_flows))
            print("System Uptime in Milliseconds: " + str(self.uptime))
            print("Time since Epoch in Milliseconds: " + str(self.epoch_ms))
            print("Residual Nanoseconds from Above: " + str(self.epoch_ns))
            print("Total Number of Flows Since Boot: " + str(self.total_flows))
            print("Engine Type: " + str(self.engine_type))
            print("Engine ID: " + str(self.engine_id))
            print("Sampling Interval: " + str(self.sample_rate))
        else:
            print("Version do not supported.")
