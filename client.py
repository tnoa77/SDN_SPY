from scapy.all import *
import time
import os

RANDOM_IP_POOL = ['0.0.0.0/0']


def get_data(id):
    return "SDNSPY_" + id + "_"


def get_random_port():
    return int(random.uniform(10000, 60000))


def get_random_tos():
    return int(random.uniform(0, 8))


def get_random_ip():
    str_ip = RANDOM_IP_POOL[random.randint(0, len(RANDOM_IP_POOL) - 1)]
    str_ip_addr = str_ip.split('/')[0]
    str_ip_mask = str_ip.split('/')[1]
    ip_addr = struct.unpack('>I', socket.inet_aton(str_ip_addr))[0]
    mask = 0x0
    for i in range(31, 31 - int(str_ip_mask), -1):
        mask |= 1 << i
    ip_addr_min = ip_addr & (mask & 0xffffffff)
    ip_addr_max = ip_addr | (~mask & 0xffffffff)
    return socket.inet_ntoa(struct.pack('>I', random.randint(ip_addr_min, ip_addr_max)))


def get_random_mac():
    mac = [0x52, 0x54, 0x00,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def send_udp(packet):
    data = packet.load
    packet.load = data + "SEND_1"
    sendp(packet)
    time.sleep(1)
    packet.load = data + "SEND_2"
    sendp(packet)
    time.sleep(1)


ip_dst = "10.0.0.1"
ip_src = "10.0.0.2"
mac_dst = "00:00:00:00:00:01"
mac_src = os.popen("cat /sys/class/net/h2-eth0/address").readline()
mac_src = mac_src.strip()

os.system("iptables -F")
os.system("iptables -A INPUT -p udp --dport 10000:60000 -j DROP")
os.system("iptables -A INPUT -p udp --dport 9250 -j DROP")
os.system("tcpdump -t udp -w ./client.pcap&>/dev/null")

pkt = Ether(src=mac_src, dst=mac_dst) / IP(src=ip_src, dst=ip_dst) / UDP(sport=9250, dport=9250) / "SDNSPY_start"
sendp(pkt)
time.sleep(1)

print "change dst port"
pkt = Ether(src=mac_src, dst=mac_dst) / IP(src=ip_src, dst=ip_dst) / UDP(sport=9250, dport=get_random_port()) / get_data("D1")
send_udp(pkt)

print "change src port"
pkt = Ether(src=mac_src, dst=mac_dst) / IP(src=ip_src, dst=ip_dst) / UDP(sport=get_random_port(), dport=9250) / get_data("D2")
send_udp(pkt)

print "change ToS bits"
pkt = Ether(src=mac_src, dst=mac_dst) / IP(src=ip_src, dst=ip_dst, tos=get_random_tos()) / UDP(sport=9250, dport=9250) / get_data("D3")
send_udp(pkt)

print "change src IP"
pkt = Ether(src=mac_src, dst=mac_dst) / IP(src=ip_src, src=get_random_ip(), dst=ip_dst) / UDP(sport=9250, dport=9250) / get_data("D4")
send_udp(pkt)

# print "change dst IP"
# pkt = Ether(dst=mac_dst) / IP(dst=get_random_ip()) / UDP(sport=9250, dport=9250) / get_data("D5")
# send_udp(pkt)

print "change src MAC"
rd_mac = get_random_mac()
os.system("ip link set h2-eth0 address " + rd_mac)
os.system("arp -s " + ip_dst + " " + mac_dst)

pre_pkt = Ether(src=rd_mac) / IP(dst="10.0.0.10") / ICMP()
sendp(pre_pkt)
time.sleep(1)

pkt = Ether(src=rd_mac, dst=mac_dst) / IP(src=ip_src, dst=ip_dst) / UDP(sport=9250, dport=9250) / get_data("D5")
send_udp(pkt)

pkt = Ether(dst=mac_dst) / IP(dst=ip_dst) / UDP(sport=9250, dport=9250) / "SDNSPY_exit"
sendp(pkt)

os.system("killall tcpdump")
