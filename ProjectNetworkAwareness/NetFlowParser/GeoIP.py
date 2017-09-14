from geolite2 import geolite
from math import sin, cos, atan2, radians, degrees, sqrt
import sys, os
sys.path.insert(0, os.path.abspath('..'))
from  Utils.Constants import Constants
constants = Constants()

class GeoIP(object):
    ip = None
    def __init__(self, ip):
        self.ip = ip
        self.countryName = None
        self.continentName = None
        self.registeredCountry = None
        self.latitude = None
        self.longitude = None
        reader = geolite2.reader()
        info = reader.get(self.ip)
        self.fill(info['country']['names']['en'],
                  info['continent']['names']['en'],
                  info['registered_country']['names']['en'],
                  info['location']['latitude'],
                  info['location']['longitude'])
        geolite2.close()
        self.angle = self.getAngle(self.latitude, self.longitude)
        self.distance = self.getDistance(self.latitude, self.longitude)

    def fill(self, countryName, continentName, registeredCountry, latitude, longitude):
        self.countryName = countryName
        self.continentName = continentName
        self.registeredCountry = registeredCountry
        self.latitude = latitude
        self.longitude = longitude

    def getAngle(self, latitude, longitude):
        # 2
        latitude = radians(latitude)
        longitude = radians(longitude)
        # 1
        subLat = latitude - constants.localLatitude
        subLon = longitude - constants.localLongitude

        y = sin(subLon) * cos(longitude)

        x = cos(constants.localLatitude) * sin(latitude) - sin(constants.localLatitude) * cos(latitude) * cos(subLon)
        angle = atan2(y, x)

        angle = degrees(angle)
        angle = (angle + 360) % 360
        angle = 360 - angle  # count degrees counter-clockwise
        return angle

    def getDistance(self, latitude, longitude):
        #Earth radius in km
        R = 6373.0

        # 2
        latitude = radians(latitude)
        longitude = radians(longitude)
        # 1
        subLat = latitude - constants.localLatitude
        subLon = longitude - constants.localLongitude

        a = (sin(subLat / 2)) ** 2 + cos(constants.localLatitude) * cos(latitude) * (sin(subLon / 2)) ** 2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))
        return R * c

    def __dict__(self):
        return {'ip':                   self.ip,
                'countryName':          self.countryName,
                'continentName':        self.continentName,
                'registeredCountry':    self.registeredCountry,
                'latitude':             self.latitude,
                'longitude':            self.longitude,
                'angle':                self.angle,
                'distance':             self.distance}