from scapy.all import *

mac_dst = "00:00:00:00:00:02"

while True:
    receive = sniff(filter="udp", count=1)
    receive[0]