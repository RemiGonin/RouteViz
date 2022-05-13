import pyshark

capture = pyshark.LiveCapture(interface='wlan0', display_filter="icmp")
for packet in capture.sniff_continuously(packet_count=500):
    try:
        if int(packet.icmp.code) == 0: #check if the packet is indeed a icpm that expired
            print('hop info:', packet.icmp.udp_possible_traceroute) #get expert message with hop # and attemps #
            print("source: ", packet.ip.src) #get where the packet stopped (source from pov of this script)
            print("dest: ", packet.icmp.ip_dst) #get initial destination (ip used to traceroute)
    except:
        pass