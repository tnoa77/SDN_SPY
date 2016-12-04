from scapy.all import *

mac_dst = "00:00:00:00:00:02"

while True:
    receive = sniff(filter="udp", count=1)
    if hasattr(receive[0], 'load') and str(receive[0].load).startswith("SDN_SPY_"):
        receive[0].show()
