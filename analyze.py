from scapy.all import *

client_pacp = rdpcap("client.pcap")
server_pacp = rdpcap("server.pcap")

client_time = []
server_time = []

for i in range(0, len(client_pacp)):
    packet = client_pacp[i]
    if hasattr(packet, 'load') and str(packet.load).startswith("SDN_SPY_D"):
        print packet.load
        client_time.append(packet.time)

print "==================="

for i in range(0, len(server_pacp)):
    packet = server_pacp[i]
    if hasattr(packet, 'load') and str(packet.load).startswith("SDN_SPY_D"):
        print packet.load
        server_time.append(packet.time)

print "NO.\tP1_SEND\tP1_RECV\tP2_SEND\tP2_RECV"
if len(client_time) == len(server_time):
    for i in range(0, len(client_time), 4):
        print "P%d\t%d\t%d\t%d\t%d" % (
            (i / 4), int(server_time[i] - client_time[i]), int(server_time[i + 1] - client_time[i + 1]),
            int(server_time[i + 2] - client_time[i + 2]), int(server_time[i + 3] - client_time[i + 3]))
else:
    print "data mismatch"
