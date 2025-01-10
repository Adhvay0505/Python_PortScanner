from scapy.all import *

try:
    host = input("Enter host address: ")
    p = list(input("Enter the ports to be scanned: ").split(","))
    temp = map(int, p)
    ports = list(temp)

    if(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",host)):
        print("\n\n Scanning...")
        print("Hosts: ",host)
        print("Ports: ",ports)

        ans,unans = sr(IP(dst=host)/TCP(dport=ports, flags="S"), verbose=0, timeout=2)

        for(s,r) in ans:
            print("[+] {} Open".format(s[TCP].dport))


except(RuntimeError, ValueError, TypeError, NameError):
    print("[-] Some error occured")
    print("[-] Exiting...")

