#################################################
#Thresholds (THRESHOLD) - in mbps
#################################################

THRESHOLD_WARNING = 30
THRESHOLD_BLOCKING = 50

THRESHOLD_HOST_BLOCKING = 10
THRESHOLD_HOST_WARNING = 5
THRESHOLD_HOST_SINGLE_CONNECTION = 2

MAX_TIME_WINDOW_AVG_TX_TRAFFIC = 60 #seconds
MAX_TIME_WINDOW_AVG_RX_TRAFFIC = 60 #seconds

#################################################
#Hosts in the Network(s)
#################################################

NET_HOSTS = {'130.60.156.115':None} #dict of hosts

#################################################
#blockchain Config
#################################################

BC_HOST_ADDRESS = "localhost"
BC_PORT = "8545"
###
BC_CONTRACT_ABI = [{"constant":"false","inputs":[{"name":"x","type":"string"}],"name":"set_network","outputs":[],"payable":"false","type":"function"},
                   {"constant":"false","inputs":[{"name":"x","type":"string"}],"name":"report_ipv4","outputs":[],"payable":"false","type":"function"},
                   {"constant":"true","inputs":[],"name":"retrieve_ipv4","outputs":[{"name":"","type":"string"}],"payable":"false","type":"function"},
                   {"constant":"true","inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"payable":"false","type":"function"},
                   {"constant":"true","inputs":[],"name":"get_network","outputs":[{"name":"","type":"string"}],"payable":"false","type":"function"}]

###
BC_CONTRACT_ADDRESS = '0xa8480e483e6e3007b4557b03402efee04b605c15'
#BC_CONTRACT_ADDRESS = "0xb70b1450b7afeb50f68617297fbff6772a9aea11"
###
BC_ACCOUNT_ADDRESS = "0xb9cadf3eaab8f71900e76fb7e606abbaf52e2cc6"
#BC_ACCOUNT_ADDRESS = "0x7c490b5159ed034c21dfa29aa0b7c675e957b012"
BC_ACCOUNT_PASSWORD = "123456"
BC_ACCOUNT_TIME = 9999999
###
BC_TRANSACTION_TX = {'from':BC_ACCOUNT_ADDRESS, 'gas': '4700000'}

###
BC_MAX_REPORT_INTERVAL = 30 #seconds
BC_MIN_REPORT_INTERVAL = 10 #seconds
BC_MAX_RETRIEVE_INTERVAL = 60 * 2 #seconds - if the message is 5 mins old then ignore it.

###
BC_TIMESTAMP_FORMAT = '%Y-%m-%d-%H:%M:%S'

#################################################
#Protection Configuration (def)
#################################################

DEF_IDLE_TIMEOUT = 20 #seconds

