import scapy.all as scapy
from scapy.layers import http
from scapy.layers import inet
import subprocess

verb = 1

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=analysis)

def analysis(packet):
    if packet.haslayer(http.HTTPRequest):
        if verb == 1:
            pass
        elif verb == 2:
            print(packet.summary())
        elif verb == 3:
            verbose_3(packet)
        elif verb == 4:
            verbose_4(packet)
        elif verb == 5:
            print(packet.show())

        url = get_url(packet)
        print("[+] Extracting URL ")
        print(url)

        if packet.haslayer(scapy.Raw):
            print("[+] This packet contains RAW data sent using HTTP and it might include usernames and passwords")
            rawstr = str(packet[scapy.Raw])
            userpass_detect(rawstr)
        else:
            print("[-] This Packet does not have a RAW field")

def userpass_detect(rawstr):
    keywrds = ['username', 'user', 'password', 'pass', 'userpass', 'uname', 'login', 'cred', 'admin', 'user']
    has_username = False

    for keywrd in keywrds:
        if keywrd in rawstr:
            print("[***] Contains Username and Password field")
            has_username = True
    if not has_username:
        print("[-] Does not seem to contain Username and Password in RAW field")
    print(rawstr)

def get_url(pack):
    url_host = pack[http.HTTPRequest].Host
    url_path = pack[http.HTTPRequest].Path
    url = url_host + url_path
    return url

def verbose_3(pack):
    print("Source IP\t\t" + str(pack[inet.IP].src))
    print("Destination IP\t\t" + str(pack[inet.IP].dst))
    print("Length\t\t\t" + str(pack[inet.IP].len))
    print("Method\t\t\t" + str(pack[http.HTTPRequest].Cethod))
    print("Cookie\t\t\t" + str(pack[http.HTTPRequest].Cookie))
    print("Date\t\t\t" + str(pack[http.HTTPRequest].date))

def verbose_4(pack):
    verbose_3(pack)
    print("Source Port\t\t" + str(pack[inet.TCP].sport))
    print("Destination Port\t" + str(pack[inet.TCP].dport))
    print("Seq\t\t\t" + str(pack[inet.TCP].seq))
    print("Ack\t\t\t" + str(pack[inet.TCP].ack))
    print("Flags\t\t\t" + str(pack[inet.TCP].flags))
    print("From\t\t\t" + str(pack[http.HTTPRequest].From))
    print("Origin\t\t\t" + str(pack[http.HTTPRequest].Origin))
    print("Proxy_Authorization\t" + str(pack[http.HTTPRequest].Proxy_Authorization))
    print("Referer\t\t\t" + str(pack[http.HTTPRequest].Referer))

def intro():
    while True:
        print("\n1> Run Ifconfig to find out interfaces")
        print("2> enter Interface and start sniffing")
        choice = int(input("3> Exit\n"))

        if choice == 1 :
            subprocess.call('ifconfig')
        if choice == 2:
            interface = input("Enter Interface\n")
            global verb
            verb = int(input('Enter Verbosity (1 is least, 5 is maximum, and the ideal values are 3 and 4)\n')) or 1
            sniffer(interface)
        if choice == 3:
            exit(1)

intro()