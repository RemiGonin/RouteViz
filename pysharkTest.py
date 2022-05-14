import pyshark
import pexpect




def getOutgoingPacket():
    captureOutgoingPackets = pyshark.LiveCapture(interface='wlan0', display_filter="tcp")
    for packet in captureOutgoingPackets.sniff_continuously():
        #SYN : 0x...2 FIN : 0x...11
        if str(packet.tcp.flags)[-2:] == "02":
            destIp = str(packet.ip.dst)
            sendTraceRoute(destIp)

    return 1

def sendTraceRoute(destIp):
    child = pexpect.spawn(str("traceroute -q 1 -w 1 " + str(destIp)))

    while 1:
        line = child.readline()
        if not line: break
        print(line)

sendTraceRoute("8.8.8.8")


captureTracerouteReturn = pyshark.LiveCapture(interface='wlan0', display_filter="icmp")

a = getOutgoingPacket()

for packet in captureTracerouteReturn.sniff_continuously():
 
    if int(packet.icmp.code) == 0: #check if the packet is indeed a icpm that expired
        print('hop info:', packet.icmp.udp_possible_traceroute) #get expert message with hop # and attemps #
        print("source: ", packet.ip.src) #get where the packet stopped (source from pov of this script)
        print("dest: ", packet.icmp.ip_dst) #get initial destination (ip used to traceroute)



