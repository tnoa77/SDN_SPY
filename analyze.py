from scapy.all import *

client_pacp = rdpcap("client.pcap")
server_pacp = rdpcap("server.pcap")

tags = []
client_time = {}
server_time = {}
title_dict = {"D1": "DST_PORT", "D2": "SRC_PORT", "D3": "TOS", "D4": "SRC_IP", "D5": "SRC_MAC"}


# SDNSPY_D1_SEND_1
# group: D1, type: SEND, no: 1
def analyze_data(data):
    rel = data.split("_")
    if len(rel) == 4:
        group = rel[1]
        direction = rel[2]
        no = rel[3]
        return group, direction, no


def calc_time_diff(group, direction=1):
    if group in client_time.keys() and group in server_time.keys():
        if direction == 1:
            return (server_time[group] - client_time[group]) * 100000000
        else:
            return (client_time[group] - server_time[group]) * 100000000
    else:
        return "NaN"


for i in range(0, len(client_pacp)):
    packet = client_pacp[i]
    if hasattr(packet, 'load') and str(packet.load).startswith("SDNSPY_D"):
        group, direction, no = analyze_data(packet.load)
        tags.append(group)
        client_time[group + "_" + direction + "_" + no] = packet.time

for i in range(0, len(server_pacp)):
    packet = server_pacp[i]
    if hasattr(packet, 'load') and str(packet.load).startswith("SDNSPY_D"):
        group, direction, no = analyze_data(packet.load)
        tags.append(group)
        client_time[group + "_" + direction + "_" + no] = packet.time

print "%10s%15s%15s%15s%15s" % ("FIELD", "P1_SEND", "P1_RECV", "P2_SEND", "P2_RECV")
for group in tags:
    print "%10s%15.2f%15.2f%15.2f%15.2f" % (
        (title_dict[group]), calc_time_diff(group + "_SEND_1", 1),
        calc_time_diff(group + "_RECV_1", 0),
        calc_time_diff(group + "_SEND_2", 1),
        calc_time_diff(group + "_RECV_2", 0))
