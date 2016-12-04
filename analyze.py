from scapy.all import *

client_pacp = rdpcap("client.pcap")
server_pacp = rdpcap("server.pcap")

client_time = []
server_time = []

for i in range(0, len(client_pacp)):
    packet = client_pacp[i]
    if hasattr(packet, 'load') and str(packet.load).startswith("SDN_SPY_D"):
        print packet.time
        client_time.append(packet.time)

print "==================="

for i in range(0, len(server_pacp)):
    packet = server_pacp[i]
    if hasattr(packet, 'load') and str(packet.load).startswith("SDN_SPY_D"):
        print packet.time
        server_time.append(packet.time)

print "NO.\tP1_SEND\tP1_RECV\tP2_SEND\tP2_RECV"
if len(client_time) == len(server_time):
    for i in range(0, len(client_time), 4):
        print "D%d\t%2f\t%2f\t%2f\t%2f" % (
            (i / 4 + 1), (server_time[i] - client_time[i]) * 100000000,
            (client_time[i + 1] - server_time[i + 1]) * 100000000,
            (server_time[i + 2] - client_time[i + 2]) * 100000000,
            (client_time[i + 3] - server_time[i + 3]) * 100000000)
else:
    print "data mismatch"
