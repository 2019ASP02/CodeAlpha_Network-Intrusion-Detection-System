from scapy.all import sniff ,TCP,IP,UDP

#Vulnerable ports  FTP, SSH, Telnet,SMTP,TCP, HTTP, HTTPS
suspicious_ports = [21, 22, 23, 25, 80, 443, 8080]
max_package_size = 1500  #packet size
alert_log = "nids_alerts.log" #create text file to save and update the file


def log_alert(msg):
    with open(alert_log,"a") as log_file: # open file and add the activities log
        log_file.write(f"{msg}\n")
    print(msg)

def detect_intrusion(packet):# function detect the  intrusion
    if IP in packet:
        source_ip = packet[IP].src #find the sourcce ip
        destination_ip = packet[IP].dst #find the destination function
        packet_size = len(packet) #find the length of the packeg

        if TCP in packet and packet[TCP].dport in suspicious_ports: # if that packet is TCP
            log_alert(f"SUSPICIOUS TCP ACTIVITY DETECTED: {source_ip} -> {destination_ip} on port {packet[TCP].dport}")#print the msg

        if UDP in packet and packet[UDP].dport in suspicious_ports:# if that pavket is UDP
            log_alert(f"SUSPICIOUS UDP ACTIVITY DETECTED: {source_ip} -> {destination_ip} on port {packet[UDP].dport} ")#print the msg

        if packet_size > max_package_size:#if packet size larger than max packet size
            log_alert(f"Largest packet detected from {source_ip} to {destination_ip}. size : {packet_size} bytes") #print the msg

def start_sniffer(interface = "Wi-Fi"):#define the sniffer defaultly initial interface as Wi-Fi
    print(f"Starting packet sniffing on inferface: {interface}")
    sniff(iface = interface, prn = detect_intrusion, store = False)#assign the parameter

if __name__ == "__main__":
    try:
        network_interface = input("Enter the network interface to monitor (eg:eth0,Wi-Fi) : ")#input interface take user 
        start_sniffer(interface = network_interface)#call the sniffer
    except KeyboardInterrupt:#'CTRL + C' to intrrupt the NIDS
        print("\nExiting NIDS....\nGood Bye\n")
        