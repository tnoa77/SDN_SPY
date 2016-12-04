from scapy.all import *

mac_dst = "00:00:00:00:00:02"

listenAddress = ('10.0.0.1', 9250)
socketServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socketServer.bind(listenAddress)

while True:
    data, clintAddress = socketServer.recvfrom(2048)
    print "received:", data, "from", clintAddress

socketServer.close()
