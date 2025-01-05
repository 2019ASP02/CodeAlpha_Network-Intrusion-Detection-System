from scapy import sniff ,TCP,IP,UDP

#Vulnerable ports  FTP, SSH, Telnet,SMTP,TCP, HTTP, HTTPS
suspicious_ports = [21, 22, 23, 25, 80, 139, 443, 8080, 8443]
max_package_size = 1500  #
alert_log = "nids_alerts.log"


def log_alert(msg):
    with open(alert_log,"a") as log_file:
        log_file.write(f"{msg}\n")
    print(msg)

def detect_intrusion(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)

    if TCP in packet and packet[TCP].dprot in suspicious_ports:
        log_alert(f"SUSPICIOUS TCP ACTIVITY DETECTED: {source_ip} -> {destination_ip} on port {packet[TCP].dprot}")

    if UDP in packet and packet[UDP].dport in suspicious_ports:
        log_alert(f"SUSPICIOUS UDP ACTIVITY DETECTED: {source_ip} -> {destination_ip} on port {packet[UDP].dport} ")

    if packet_size > max_package_size:
        log_alert(f"Largest packet detected from {source_ip} to {destination_ip}. size : {packet_size} bytes")

def start_sniffer(interface = 'Wi-Fi'):
    print(f"Starting packet sniffing on inferface: {interface}")
    sniff(iface = interface, prn = detect_intrusion, store = False)

if __name__ == __main__:
    try:
        network_interface = input("Enter the network interface to monitor (eg:eth0,Wi-Fi) : ")
        start_sniffer(interface = network_interface)
    except KeyboardInterrupt:
        print("\nExiting NIDS....\nGood Bye\n")
        