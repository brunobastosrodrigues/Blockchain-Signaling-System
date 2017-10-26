import time
from scapy.all import *
from threading import Thread
from collections import Counter
from datetime import datetime

'''
Tested on Ubuntu 16.04
- monitor sent/recv traffic for a list of hosts in a specific interface
'''

in_traffic = Counter( )
out_traffic = Counter( )

INTERFACE = 'enp0s25' #adjust to your interface

hosts = {'130.60.156.115':None} #Modify!
prev_ts = None #previous timestamp

##############################
def get_avg_stats():
    # Return
    # aux_hosts: average in and out traffic per host
    # delta_ts: difference in seconds between current and previous timestamp
    global hosts, prev_ts
    curr_ts = datetime.now()
    if not prev_ts:
        prev_ts = curr_ts
    else:
        delta_ts = (curr_ts - prev_ts).seconds
        for ip, stats in hosts.iteritems():
            inbound, outbound = stats
            avg_mbits_in = bytes_to_mbits(inbound)/delta_ts
            avg_mbits_out = bytes_to_mbits(outbound)/delta_ts
            hosts[ip] = avg_mbits_in, avg_mbits_out
            prev_ts = curr_ts
    aux_hosts = hosts
    hosts = hosts.fromkeys(hosts, None)
    return aux_hosts, delta_ts
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
        for ip, stats in hosts.iteritems():
            src = pkt[IP].src
            dst = pkt[IP].dst
            if ip == src:
                out_traffic[ip] += pkt.len
            elif ip == dst:
                in_traffic[ip] += pkt.len
            hosts[ip] = in_traffic[ip], out_traffic[ip]

def sniffer():
    sniff(iface=INTERFACE, filter="ip", prn=monitor_callback, store=False)

t0 = Thread(target=sniffer)
t0.start()

def debug():
    global hosts
    while True:
        try:
            for ip, stats in hosts.iteritems():
                inbound, outbound = stats
                print ip, bytes_to_mbits(inbound), bytes_to_mbits(outbound)
            time.sleep(1)
        except:
            pass

t1 = Thread(target=debug)
t1.start()