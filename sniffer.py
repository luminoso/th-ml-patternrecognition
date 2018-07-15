import argparse
import logging
import pcapy
import threading
import time
import collections

from impacket import ImpactDecoder
from impacket import ImpactPacket
from pymongo import MongoClient

count = 0
keep_running = True
statistics_wait = 0
capture = None
circular_buffer = collections.deque(maxlen=10)


def print_statistics():
    global keep_running, count, circular_buffer

    while keep_running:
        logging.info("Total captures so far: {}. Queue: {}".format(count,circular_buffer))
        time.sleep(statistics_wait)

        circular_buffer.append(count)

        if circular_buffer.count(count) == len(circular_buffer) and len(circular_buffer) == circular_buffer.maxlen:
            logging.info("Re-init capture...")
            circular_buffer = collections.deque(maxlen=10)
            init()
            time.sleep(statistics_wait*2)



def getProtocol(protocol):
    """
    Decodes protocol type in order to fill JSON structure
    :param protocol: captured packet
    :return: protocol name
    """
    if protocol == ImpactPacket.UDP.protocol:
        return "UDP"
    elif protocol == ImpactPacket.TCP.protocol:
        return "TCP"
    elif protocol == ImpactPacket.ICMP.protocol:
        return "ICMP"
    else:
        return "OTHER"


def getSrcPort(ip):
    protocol = ip.get_ip_p()
    if protocol == ImpactPacket.UDP.protocol:
        return ip.child().get_uh_sport()
    elif protocol == ImpactPacket.TCP.protocol:
        return ip.child().get_th_sport()


def getDstPort(ip):
    protocol = ip.get_ip_p()
    if protocol == ImpactPacket.UDP.protocol:
        return ip.child().get_uh_dport()
    elif protocol == ImpactPacket.TCP.protocol:
        return ip.child().get_th_dport()


def sniff(collection, db_ip):
    global capture, count
    while True:

        try:
            (header, content) = capture.next()
            eth = ImpactDecoder.EthDecoder().decode(content)
            ip = eth.child()
        except Exception as e:
            logging.debug("Couldn't retrieve packet: {}".format(content))
            logging.debug(e)
            logging.info("Waiting more capture due to interface change/suspend/resume/whatever...")
            time.sleep(1)
            continue
        try:
            if ip.get_ip_src() in db_ip or ip.get_ip_dst() in db_ip:
                continue
        except:
            logging.debug("Couldn't retrieve ip src/dst")
            time.sleep(0.2)
            continue

        count = count + 1
        protocol = ip.get_ip_p()
        logging.debug('{:<4} ORIGIN:(IP:{:<16} PORT:{:<5} ) DST:(IP:{:<16} PORT:{:<5}) LEN:{:>5}'.format(
            getProtocol(protocol),
            ip.get_ip_src(),
            str(getSrcPort(ip)),
            ip.get_ip_dst(),
            str(getDstPort(ip)),
            header.getlen()))

        if protocol == ImpactPacket.UDP.protocol:
            pkt = {"protocol": 'UDP',
                   "length": header.getlen(),
                   "origin": {
                       "ip": ip.get_ip_src(),
                       "port": getSrcPort(ip)
                   },
                   "destination": {
                       "ip": ip.get_ip_dst(),
                       "port": getDstPort(ip)
                   },
                   "timestamp": time.time()}

        elif protocol == ImpactPacket.TCP.protocol:
            trans = ip.child()
            pkt = {"protocol": 'TCP',
                   "length": header.getlen(),
                   "origin": {
                       "ip": ip.get_ip_src(),
                       "port": getSrcPort(ip)
                   },
                   "destination": {
                       "ip": ip.get_ip_dst(),
                       "port": getDstPort(ip)
                   },
                   "tcp_flags": {
                       "SYN": trans.get_SYN(),
                       "FIN": trans.get_FIN(),
                       "RST": trans.get_RST()},
                   "timestamp": time.time()}
        else:
            pkt = {"protocol": 'ICMP',
                   "length": header.getlen(),
                   "origin": {
                       "ip": ip.get_ip_src(),
                   },
                   "destination": {
                       "ip": ip.get_ip_dst(),
                   },
                   "timestamp": time.time()}

        collection.insert_one(pkt)


def init():
    global capture

    # start the sniffing session
    capture = pcapy.open_live(args.interface, 65536, 1, 100)
    logging.info("Listening on %s: net=%s, mask=%s, linktype=%d" % (
        args.interface, capture.getnet(), capture.getmask(), capture.datalink()))

if __name__ == '__main__':
    start_time = time.time()

    # CLI arguments
    parser = argparse.ArgumentParser(description='Python Sniffer',
                                     epilog='Available interfaces:\n{}'.format(pcapy.findalldevs()))

    parser.add_argument("collection_name",
                        help='Collection to store the capture',
                        type=str,
                        default="test_db")

    parser.add_argument("interface",
                        help='Network interface to monitor')

    parser.add_argument("-v", help="Increase output verbosity",
                        action="store_true")

    parser.add_argument("-db", help="Database to use (default: thesis)",
                        type=str,
                        default="thesis")

    parser.add_argument("-t", help="Print statistics every T seconds (default: 5)",
                        default=5, type=int)

    args = parser.parse_args()

    # set the appropriate logging level
    if args.v:
        logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)

    # connect to mongodb
    client = MongoClient('mongodb://nuno:nunotpr@glua.ua.pt:22070/')
    db = client[args.db]
    collection = db[args.collection_name]
    logging.info("DB: {}".format(db))
    logging.info("Mongo Collection: {}".format(collection))

    # setup session exclusions and start capturing to database
    exclusions = ["193.136.175.23"]
    logging.info("Excluding IP from capture: " + str(exclusions))

    logging.debug("Thread stats every {} seconds...".format(args.t))
    statistics_wait = args.t
    t = threading.Thread(target=print_statistics)
    t.start()

    init()

    logging.debug("Starting capture..")

    while True:
        try:
            sniff(collection, exclusions)

        except KeyboardInterrupt:
            keep_running = False
            t.join()
            logging.info('\n\nEnd of capture. Total packets: {}'.format(count))
            logging.info('recv: {0[0]}, drop: {0[1]}, ifdrop: {0[2]}'.format(capture.stats()))
            logging.info("Runtime: {} minutes".format((time.time() - start_time) / 60))
            exit(0)

        except Exception as e:
            logging.info("Restarting because reasons")
            logging.info(e.message)
            time.sleep(1)
