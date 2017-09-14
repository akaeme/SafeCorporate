from netaddr import IPAddress, IPNetwork
import os, sys
sys.path.insert(0, os.path.abspath('..'))
from  Utils.Constants import Constants
from geolite2 import geolite2
from math import sin, cos, atan2, radians, sqrt, degrees
from statistics import mean, variance
from numpy import array, percentile
from scipy.stats import skew, kurtosis
constants_ = Constants()

weekdays = {'Monday':0,
            'Tuesday':1,
            'Wednesday':2,
            'Thursday':3,
            'Friday':4,
            'Saturday':5,
            'Sunday':6}

class TimeFrame(object):
    def __init__(self, timewindow):
        super(TimeFrame, self).__init__()
        #Delta time - start epoch end - epoch
        self.weekday = 0
        self.start = 0
        self.end = 0
        self.timewindow = timewindow
        # Auxiliary variables
        self.consecutivePacketsIn = {}
        self.consecutivePacketsOut = {}
        self.connections = {}
        # variables to count
        # In means traffic from inside to outside
        self.bytesIn = []
        self.packetsIn = []
        # privileged ports
        self.privPortsIn = []
        # non privileged ports
        self.portsIn = []
        self.synFlagsIn = []
        self.finFlagsIn = []
        self.rstFlagsIn = []
        self.distances = []
        self.angles = []
        # calculated when getter is invoked
        self.deltaIn = 0
        # number of ips contacted
        self.numberIpContacted = []

        # Out means traffic from outside to inside
        self.bytesOut = []
        self.packetsOut = []
        # privileged ports
        self.privPortsOut = []
        # non privileged ports
        self.portsOut = []
        self.synFlagsOut = []
        self.finFlagsOut = []
        self.rstFlagsOut = []

        # calculated when getter is invoked
        self.deltaOut = 0

    # check non private networks and multicast
    # ip - IPAddress
    def checkNonPrivateIP(self, ip):
        privateNetworks = list(constants_.ipClassesPrivate.keys()) + list(constants_.ipClasses.keys())
        for network in privateNetworks:
            if ip in network:
                return False
        return True

    def add(self, doc):
        srcIP = IPAddress(doc['srcIP'])
        dstIP = IPAddress(doc['dstIP'])
        bytes = doc['bytes']
        synFlag = doc['synFlag']
        finFlag = doc['finFlag']
        rstFlag = doc['rstFlag']
        numberPackets = doc['numberPackets']
        #srcPort = doc['srcPort']
        dstPort = doc['dstPort']
        #hours = doc['hours']
        #minutes = doc['minutes']
        #seconds = doc['seconds']
        epoch_ms = doc['epoch']
        if self.start == 0:
            self.start = epoch_ms
            self.weekday = weekdays[doc['weekday']]
        # Inside to outside
        if srcIP in IPNetwork(constants_.ENTERPRISE_SUBNET):
            if self.checkNonPrivateIP(dstIP):
                self.bytesIn.append(bytes)
                self.synFlagsIn.append(synFlag)
                self.finFlagsIn.append(finFlag)
                self.rstFlagsIn.append(rstFlag)
                self.packetsIn.append(numberPackets)
                if dstPort < 1024:
                    self.privPortsIn.append(1)
                else:
                    self.portsIn.append(1)
                if str(dstIP) not in list(self.consecutivePacketsIn.keys()):
                    self.consecutivePacketsIn[str(dstIP)] = [epoch_ms]
                else:
                    self.consecutivePacketsIn[str(dstIP)].append(epoch_ms)
                if str(dstIP) not in self.numberIpContacted:
                    self.numberIpContacted.append(str(dstIP))
                #print(self.processGeoIP(str(dstIP)))
                angle, distance = self.processGeoIP(str(dstIP))
                self.angles.append(angle)
                self.distances.append(distance)
                if str(dstIP) in self.connections.keys():
                    self.connections[str(dstIP)] += 1
                else:
                    self.connections[str(dstIP)] = 1
        # Outside to Inside
        else:
            self.bytesOut.append(bytes)
            self.synFlagsOut.append(synFlag)
            self.finFlagsOut.append(finFlag)
            self.rstFlagsOut.append(rstFlag)
            self.packetsOut.append(numberPackets)
            if dstPort < 1024:
                self.privPortsOut.append(1)
            else:
                self.portsOut.append(1)
            if str(dstIP) not in list(self.consecutivePacketsOut.keys()):
                self.consecutivePacketsOut[str(dstIP)] = [epoch_ms]
            else:
                self.consecutivePacketsOut[str(dstIP)].append(epoch_ms)

    def getFeaturesSmallTimeWindow(self, doc, classification):
        deltasIn = dict([(k, v) for k, v in self.consecutivePacketsIn.items() if len(v) > 1])
        deltasOut = dict([(k, v) for k, v in self.consecutivePacketsOut.items() if len(v) > 1])
        connectedIps = len(self.numberIpContacted)
        self.end = doc['epoch']
        # mean
        self.deltaIn = mean(self.processDeltas(deltasIn).values()) if len(deltasIn) > 0 else 0
        self.deltaOut = mean(self.processDeltas(deltasOut).values()) if len(deltasOut) > 0 else 0
        self.distance = mean(self.distances) if len(self.distances) > 0 else 0
        self.angle = mean(self.angles) if len(self.angles) > 0 else 0
        # mean times that he connect to same ip
        meanConnectionToSameIP = mean(self.connections.values()) if len(self.connections) > 0 else 0

        # we must filter the features before apply them in a ML model
        return {'weekday': self.weekday,
                'timeStampStart': self.start,
                'timeStampEnd': self.end,
                'timeWindow': self.timewindow,
                'bytesIn' : sum(self.bytesIn),           #to explore on big window
                'packetsIn': sum(self.packetsIn),        #to explore on big window
                'privPortsIn': sum(self.privPortsIn),
                'portsIn': sum(self.portsIn),
                'synFlagsIn': sum(self.synFlagsIn),      #to explore on big window
                'finFlagsIn': sum(self.finFlagsIn),      #to explore on big window
                'rstFlagsIn': sum(self.rstFlagsIn),      #to explore on big window
                'meanAngle': self.angle,
                'meanDistance': self.distance,
                'deltaIn': self.deltaIn,
                'connectedIps': connectedIps,           #to explore on big window
                'meanToSameIP':meanConnectionToSameIP,
                'classificationIn': classification,

                'bytesOut': sum(self.bytesOut),          #to explore on big window
                'packetsOut': sum(self.packetsOut),      #to explore on big window
                'privPortsOut': sum(self.privPortsOut),
                'portsOut': sum(self.portsOut),
                'synFlagsOut': sum(self.synFlagsOut),    #to explore on big window
                'finFlagsOut': sum(self.finFlagsOut),    #to explore on big window
                'rstFlagsOut': sum(self.rstFlagsOut),    #to explore on big window
                'deltaOut': self.deltaOut
                }

    def getFeaturesBigTimeWindow(self, doc, classification):
        deltasIn = dict([(k, v) for k, v in self.consecutivePacketsIn.items() if len(v) > 1])
        deltasOut = dict([(k, v) for k, v in self.consecutivePacketsOut.items() if len(v) > 1])
        connectedIps = len(self.numberIpContacted)
        self.end = doc['epoch']
        # mean
        #self.deltaIn = mean(self.processDeltas(deltasIn).values()) if len(deltasIn) > 0 else 0
        #self.deltaOut = mean(self.processDeltas(deltasOut).values()) if len(deltasOut) > 0 else 0
        #self.distance = mean(self.distances) if len(self.distances) > 0 else 0
        #self.angle = mean(self.angles) if len(self.angles) > 0 else 0
        # mean times that he connect to same ip
        #meanConnectionToSameIP = mean(self.connections.values()) if len(self.connections) > 0 else 0

        # Improve performance
        packetsIn = sum(self.packetsIn)
        packetsOut = sum(self.packetsOut)

        # Mean In
        meanPacketsIn = packetsIn / (packetsIn + packetsOut) if (packetsIn + packetsOut) > 0 else 0
        meanPrivPortsIn = sum(self.privPortsIn) / sum(self.privPortsIn + self.portsIn) if sum(self.privPortsIn + self.portsIn) > 0 else 0
        meanPortsIn = sum(self.portsIn) / sum(self.privPortsIn + self.portsIn) if sum(self.privPortsIn + self.portsIn) > 0 else 0
        meanSynFlagsIn = sum(self.synFlagsIn) / packetsIn if packetsIn > 0 else 0
        meanFinFlagsIn = sum(self.finFlagsIn) / packetsIn if packetsIn > 0 else 0
        meanRstFlagsIn = sum(self.rstFlagsIn) / packetsIn if packetsIn > 0 else 0

        # Mean Out
        meanPacketsOut = packetsOut / (packetsIn + packetsOut) if (packetsIn + packetsOut) > 0 else 0
        meanPrivPortsOut = sum(self.privPortsOut) / sum(self.privPortsOut + self.portsOut) if sum(self.privPortsOut + self.portsOut) > 0 else 0
        meanPortsOut = sum(self.portsOut) / sum(self.privPortsOut + self.portsOut) if sum(self.privPortsOut + self.portsOut) > 0 else 0
        meanSynFlagsOut = sum(self.synFlagsOut) / packetsOut if packetsOut > 0 else 0
        meanFinFlagsOut = sum(self.finFlagsOut) / packetsOut if packetsOut > 0 else 0
        meanRstFlagsOut = sum(self.rstFlagsOut) / packetsOut if packetsOut > 0 else 0

        # Mean in time frame
        meanPackets = mean([packetsIn, packetsOut]) if packetsIn + packetsOut > 0 else 0
        meanPrivPorts = mean([sum(self.privPortsIn), sum(self.privPortsOut)]) if (sum(self.privPortsIn) + sum(self.privPortsOut)) > 0 else 0
        meanPorts = mean([sum(self.portsIn), sum(self.portsOut)]) if (sum(self.portsIn) + sum(self.portsOut)) > 0 else 0
        meanSynFlags = mean([sum(self.synFlagsIn), sum(self.synFlagsOut)]) if (sum(self.synFlagsIn) + sum(self.synFlagsOut)) > 0 else 0
        meanFinFlags = mean([sum(self.finFlagsIn), sum(self.finFlagsOut)]) if (sum(self.finFlagsIn) + sum(self.finFlagsOut)) > 0 else 0
        meanRstFlags = mean([sum(self.rstFlagsIn), sum(self.rstFlagsOut)]) if (sum(self.rstFlagsIn) + sum(self.rstFlagsOut)) > 0 else 0

        # Variance in time frame
        variancePackets = variance([packetsIn,packetsOut]) if packetsIn + packetsOut > 0 else 0
        variancePrivPorts = variance([sum(self.privPortsIn),sum(self.privPortsOut)]) if (sum(self.privPortsIn) + sum(self.privPortsOut)) > 0 else 0
        variancePorts = variance([sum(self.portsIn),sum(self.portsOut)]) if (sum(self.portsIn) + sum(self.portsOut)) > 0 else 0
        varianceSynFlags = variance([sum(self.synFlagsIn),sum(self.synFlagsOut)]) if (sum(self.synFlagsIn) + sum(self.synFlagsOut)) > 0 else 0
        varianceFinFlags = variance([sum(self.finFlagsIn),sum(self.finFlagsOut)]) if (sum(self.finFlagsIn) + sum(self.finFlagsOut)) > 0 else 0
        varianceRstFlags = variance([sum(self.rstFlagsIn),sum(self.rstFlagsOut)]) if (sum(self.rstFlagsIn) + sum(self.rstFlagsOut)) > 0 else 0

        # Using method
        meanBytesIn, varianceBytesIn, skewBytesIn, kurtosisBytesIn, firstQBytesIn, thirdQBytesIn = self.processStatically(self.bytesIn)
        meanDeltaIn, varianceDeltaIn, skewDeltaIn, kurtosisDeltaIn, firstQDeltaIn, thirdQDeltaIn = self.processStatically(self.processDeltas(deltasIn).values())

        meanBytesOut, varianceBytesOut, skewBytesOut, kurtosisBytesOut, firstQBytesOut, thirdQBytesOut = self.processStatically(self.bytesOut)
        meanDeltaOut, varianceDeltaOut, skewDeltaOut, kurtosisDeltaOut, firstQDeltaOut, thirdQDeltaOut = self.processStatically(self.processDeltas(deltasOut).values())

        meanDistance, varianceDistance, skewDistance, kurtosisDistance, firstQDistance, thirdQDistance = self.processStatically(self.distances)
        meanAngle, varianceAngle, skewAngle, kurtosisAngle, firstQAngle, thirdQAngle = self.processStatically(self.angles)
        meanConnectionToSameIP, varianceConnectionToSameIP, skewConnectionToSameIP, kurtosisConnectionToSameIP, firstQConnectionToSameIP, thirdQConnectionToSameIP = self.processStatically(self.connections.values())

        # we must filter the features before apply them in a ML model
        return {'weekday': self.weekday,
                'timeStampStart': self.start,
                'timeStampEnd': self.end,
                'timeWindow': self.timewindow,
                'bytesIn': sum(self.bytesIn),
                'meanBytesIn': meanBytesIn,
                'varianceBytesIn': varianceBytesIn,
                'skewBytesIn': skewBytesIn,
                'kurtosisBytesIn':kurtosisBytesIn,
                'firstQBytesIn': firstQBytesIn,
                'thirdQBytesIn': thirdQBytesIn,
                'packetsIn': packetsIn,
                'meanPacketsIn':meanPacketsIn,
                'meanPackets':meanPackets,
                'variancePackets':variancePackets,
                'privPortsIn': sum(self.privPortsIn),
                'meanPrivPortsIn':meanPrivPortsIn,
                'meanPrivPorts':meanPrivPorts,
                'variancePrivPorts':variancePrivPorts,
                'portsIn': sum(self.portsIn),
                'meanPortsIn':meanPortsIn,
                'meanPorts':meanPorts,
                'variancePorts':variancePorts,
                'synFlagsIn': sum(self.synFlagsIn),
                'meanSynFlagsIn':meanSynFlagsIn,
                'meanSynFlags':meanSynFlags,
                'varianceSynFlags':varianceSynFlags,
                'finFlagsIn': sum(self.finFlagsIn),
                'meanFinFlagsIn':meanFinFlagsIn,
                'meanFinFlags':meanFinFlags,
                'varianceFinFlags':varianceFinFlags,
                'rstFlagsIn': sum(self.rstFlagsIn),
                'meanRstFlagsIn':meanRstFlagsIn,
                'meanRstFlags':meanRstFlags,
                'varianceRstFlags':varianceRstFlags,
                'bytesOut': sum(self.bytesOut),
                'meanBytesOut':meanBytesOut,
                'varianceBytesOut':varianceBytesOut,
                'skewBytesOut':skewBytesOut,
                'kurtosisBytesOut':kurtosisBytesOut,
                'firstQBytesOut':firstQBytesOut,
                'thirdQBytesOut':thirdQBytesOut,
                'packetsOut': sum(self.packetsOut),
                'meanPacketsOut':meanPacketsOut,
                'privPortsOut': sum(self.privPortsOut),
                'meanPrivPortsOut':meanPrivPortsOut,
                'portsOut': sum(self.portsOut),
                'meanPortsOut':meanPortsOut,
                'synFlagsOut': sum(self.synFlagsOut),
                'meanSynFlagsOut':meanSynFlagsOut,
                'finFlagsOut': sum(self.finFlagsOut),
                'meanFinFlagsOut':meanFinFlagsOut,
                'rstFlagsOut': sum(self.rstFlagsOut),
                'meanRstFlagsOut':meanRstFlagsOut,
                'meanDeltaIn': meanDeltaIn,
                'varianceDeltaIn':varianceDeltaIn,
                'skewDeltaIn':skewDeltaIn,
                'kurtosisDeltaIn':kurtosisDeltaIn,
                'firstQDeltaIn':firstQDeltaIn,
                'thirdQDeltaIn':thirdQDeltaIn,
                'meanDeltaOut': meanDeltaOut,
                'varianceDeltaOut': varianceDeltaOut,
                'skewDeltaOut': skewDeltaOut,
                'kurtosisDeltaOut': kurtosisDeltaOut,
                'firstQDeltaOut': firstQDeltaOut,
                'thirdQDeltaOut': thirdQDeltaOut,
                'meanDistance':meanDistance,
                'varianceDistance':varianceDistance,
                'skewDistance':skewDistance,
                'kurtosisDistance':kurtosisDistance,
                'firstQDistance':firstQDistance,
                'thirdQDistance':thirdQDistance,
                'meanAngle': meanAngle,
                'varianceAngle': varianceAngle,
                'skewAngle': skewAngle,
                'kurtosisAngle': kurtosisAngle,
                'firstQAngle': firstQAngle,
                'thirdQAngle': thirdQAngle,
                'meanConnectionToSameIP': meanConnectionToSameIP,
                'varianceConnectionToSameIP': varianceConnectionToSameIP,
                'skewConnectionToSameIP': skewConnectionToSameIP,
                'kurtosisConnectionToSameIP': kurtosisConnectionToSameIP,
                'firstQConnectionToSameIP': firstQConnectionToSameIP,
                'thirdQConnectionToSameIP': thirdQConnectionToSameIP,
                'connectedIps': connectedIps,
                'classificationIn': classification,
                }

    def calculateVariance(self, mean, lst):
        diff = [i - mean for i in lst]
        square = [x**2 for x in diff]
        return sum(square)

    def processDeltas(self, deltas):
        for k, v in deltas.items():
            deltas[k] = mean([j - i for i, j in zip(v[:-1], v[1:])])
        return deltas

    def processGeoIP(self, ip):
        reader = geolite2.reader()
        info = reader.get(ip)
        latitude = info['location']['latitude']
        longitude = info['location']['longitude']
        geolite2.close()
        # Earth radius in km
        R = 6373.0

        # 2
        latitude = radians(latitude)
        longitude = radians(longitude)
        # 1
        subLat = latitude - constants_.localLatitude
        subLon = longitude - constants_.localLongitude

        a = (sin(subLat / 2)) ** 2 + cos(constants_.localLatitude) * cos(latitude) * (sin(subLon / 2)) ** 2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))
        distance = R * c

        y = sin(subLon) * cos(longitude)

        x = cos(constants_.localLatitude) * sin(latitude) - sin(constants_.localLatitude) * cos(latitude) * cos(subLon)
        angle = atan2(y, x)

        angle = degrees(angle)
        angle = (angle + 360) % 360
        angle = 360 - angle  # count degrees counter-clockwise

        return angle, distance

    def processStatically(self, data):
        data = list(data)
        if len(data) > 1:
            mean_ = mean(data)
            variance_ = variance(data)
            numPyData = array(data)
            skew_ = skew(numPyData)
            kurtosis_ = kurtosis(numPyData)
            firstQ_ = percentile(numPyData, 25)
            thirdQ_ = percentile(numPyData, 75)
            return [mean_, variance_, skew_, kurtosis_, firstQ_, thirdQ_]
        else:
            if len(data) == 1:
                return [data[0], 0,0,0,0,0]
            return [0,0,0,0,0,0]





