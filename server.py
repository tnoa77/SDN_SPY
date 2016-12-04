from scapy.all import *

mac_dst = "00:00:00:00:00:02"

os.system("tcpdump udp -w ./server.pcap")

while True:
    receive = sniff(filter="udp", count=1)
    if hasattr(receive[0], 'load') and str(receive[0].load).startswith("SDN_SPY_"):
        if str(receive[0].load) == "SDN_SPY_exit"
            break
        pkt = receive[0]
        pkt[Ether].dst = mac_dst
        sendp(pkt)

os.system("./kill_process.sh tcpdump")
print "finished"
