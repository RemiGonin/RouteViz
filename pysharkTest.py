import pyshark
import pexpect


totalIps = 0

def getOutgoingPacket():
    captureOutgoingPackets = pyshark.LiveCapture(interface='wlan0', display_filter="tcp")
    for packet in captureOutgoingPackets.sniff_continuously():
        #SYN : 0x...2 FIN : 0x...11

        #send traceroute for every outgoing SYN
        if str(packet.tcp.flags)[-2:] == "02":
            destIp = str(packet.ip.dst)
            hops = sendTraceRoute(destIp)


    return 1

def sendTraceRoute(destIp):
    child = pexpect.spawn("traceroute -q 1 -w 1 -n " + str(destIp))
    hops = []

    print("Traceroute to ", destIp)
    while 1:
        line = child.readline().decode("utf-8")
        if not line: break

        line = line.split()
        hop = line[1]
        

        # if the first word of traceroute is "*", no response
        if hop == "*":
            continue
        else:
            hops.append(hop)
            global totalIps
            totalIps += 1

    print(totalIps)
    return hops


getOutgoingPacket()


captureTracerouteReturn = pyshark.LiveCapture(interface='wlan0', display_filter="icmp")
for packet in captureTracerouteReturn.sniff_continuously():
 
    if int(packet.icmp.code) == 0: #check if the packet is indeed a icpm that expired
        print('hop info:', packet.icmp.udp_possible_traceroute) #get expert message with hop # and attemps #
        print("source: ", packet.ip.src) #get where the packet stopped (source from pov of this script)
        print("dest: ", packet.icmp.ip_dst) #get initial destination (ip used to traceroute)



# I NEED TO FIND AN API THAT ALLOWS ME TO GEOLOCATE IPS FAST ENOUGH (and preferably free)