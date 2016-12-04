from scapy.all import *

client_pacp = rdpcap("client.pcap")
server_pacp = rdpcap("server.pcap")

print len(client_pacp)
print len(server_pacp)
