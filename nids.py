from scapy import sniff ,TCP,IP,UDP

#Vulnerable ports  FTP, SSH, Telnet,SMTP,TCP, HTTP, HTTPS
suspicious_ports = [21, 22, 23, 25, 80, 139, 443, 8080, 8443]
max_package_size = 1500  #
alert_log = "nids_alerts.log"

def detect_intrusion(packet):
    

def start_sniffer(interface = 'Wi-Fi'):
    print(f"Starting packet sniffing on inferface: {interface}")
    sniff(iface = interface, prn = detect_intrusion, store = False)