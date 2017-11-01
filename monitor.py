from scapy.all import *
from threading import Thread
from collections import Counter
from datetime import datetime

'''
Tested on Ubuntu 16.04
- monitor sent/recv traffic for a list of hosts in a specific interface
'''

##########################################################################################

hosts = []

INTERFACE = 'enp0s25' #adjust to your interface
MAX_TIME_WINDOW_AVG_RX_TRAFFIC = 10
MAX_TIME_WINDOW_AVG_TX_TRAFFIC = 10

##########################################################################################

class Host( object ):

    id = None
    dpid = None
    port = None
    mac_addr = None

    rx_traffic = []
    tx_traffic = []
    tx_per_dst = {}
    rx_per_dst = {}
    avg_rx_per_src = {}
    avg_tx_per_dst = {}

    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        self.time = datetime.now()
        self.time_blocked = datetime.now()

    def set_rx_traffic(self, src, traffic):

        curr_time = datetime.now()
        delta_time = (curr_time - self.time).seconds

        if delta_time > MAX_TIME_WINDOW_AVG_RX_TRAFFIC:
            self.time = curr_time
            self.rx_traffic = [traffic]
            self.rx_per_dst[src] = [traffic]
            self.avg_rx_per_src[src] = self.get_avg_rx_traffic()
        else:
            self.rx_traffic.append(traffic)
            self.rx_per_dst[src] = self.rx_traffic
            self.avg_rx_per_src[src] = self.get_avg_rx_traffic()
        return True

    def set_tx_traffic(self, dst, traffic):

        curr_time = datetime.now()
        delta_time = (curr_time - self.time).seconds

        if delta_time > MAX_TIME_WINDOW_AVG_TX_TRAFFIC:
            self.time = curr_time
            self.tx_traffic = [traffic]
            self.tx_per_dst[dst] = [traffic]
            self.avg_tx_per_dst[dst] = self.get_avg_tx_traffic()
        else:
            self.tx_traffic.append(traffic)
            self.tx_per_dst[dst] = self.tx_traffic
            self.avg_tx_per_dst[dst] = self.get_avg_tx_traffic()
        return True

    def get_avg_tx_traffic(self):
        if float(len(self.tx_traffic)) > 0.0:
            return sum(self.tx_traffic)/float(len(self.tx_traffic))
        else:
            return 0.0

    def get_avg_rx_traffic(self):
        if float(len(self.rx_traffic)) > 0.0:
            return sum(self.rx_traffic)/float(len(self.rx_traffic))
        else:
            return 0.0

    def get_sum_tx_traffic(self):
        overall_traffic = 0.0
        for dst, traffic in self.avg_tx_per_dst.iteritems():
            overall_traffic += traffic
        return overall_traffic

    def get_sum_rx_traffic(self):
        overall_traffic = 0.0
        for src, traffic in self.avg_rx_per_src.iteritems():
            overall_traffic += traffic
        return overall_traffic

##########################################################################################
#Create our host(s)
h = Host(ip_addr='130.60.156.115')
hosts.append(h)
##########################################################################################

def get_host(hosts_list, mac=None, ip=None, dpid=None, port=None):
    '''
    Return a host by dpid/port or mac or ip
    '''
    if dpid and port:
        for h in hosts_list:
            if h.dpid == dpid and h.port == port:
                assert isinstance( h, object )
                return h
    if mac:
        for h in hosts_list:
            if h.mac_addr == mac:
                assert isinstance( h, object )
                return h
    elif ip:
        for h in hosts_list:
            if h.ip_addr == ip:
                assert isinstance( h, object )
                return h
    return None

##############################

def bytes_to_mbits(bytes):
    return ((bytes / 1024.0 / 1024.0) * 8)

def monitor_callback(pkt):
    '''
    Sniff received and transmitted packets by hosts
    hosts[ip] = total received, total transmitted (values in bytes)
    '''
    global hosts
    if pkt[IP]:

        #Checking if src and dst IP addresses are known:
        # 1 - src is known, our host is sending traffic outside
        # 2 - dst is known, our host is receiving traffic
        # 3 - src and dst are known, intra-traffic communication

        src_host = get_host(hosts, ip=pkt[IP].src)
        dst_host = get_host(hosts, ip=pkt[IP].dst)
        mbits = bytes_to_mbits(pkt.len)

        if src_host and not dst_host: #1
            src_host.set_tx_traffic(pkt[IP].dst, mbits)
        elif dst_host and not src_host: #2
            dst_host.set_rx_traffic(pkt[IP].src, mbits)
        elif src_host and dst_host: #3
            src_host.set_tx_traffic(pkt[IP].dst, mbits)
            dst_host.set_rx_traffic(pkt[IP].src, mbits)

def sniffer():
    sniff(iface=INTERFACE, filter="ip", prn=monitor_callback, store=False)

t0 = Thread(target=sniffer)
t0.daemon = True
t0.start()

def debug():
    global hosts
    while True:
        for h in hosts:
            print h.ip_addr, "rx:", h.get_avg_rx_traffic(), "tx:", h.get_avg_tx_traffic()
        time.sleep(1)

t1 = Thread(target=debug)
t1.daemon = True
t1.start()

while True:
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        exit(0)
