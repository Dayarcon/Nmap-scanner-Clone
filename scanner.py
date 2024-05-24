import nmap

scanner = nmap.PortScanner()

print("Welcome to a simple nmap atomation project")
print("<---------------------------------------------------------------->")

ip_address = input("Enter the IP address to scan: ")
print("Ip address entered: ",ip_address)
type (ip_address)
resp = input ("""\n Enter the type of scan
              1)SYN ACK Scan
              2)UDP Scan
              3)Comprehensive Scan\n""")
print("You have selected:",resp)

if resp == "1":
    print("Nmap version:", scanner.nmap_version())
    scanner.scan(ip_address, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status:",scanner[ip_address].state())
    print (scanner[ip_address].all_protocols())
    print("Open Ports:", scanner[ip_address]['tcp'].keys())
elif resp == "2":
    print("Nmap version:", scanner.nmap_version())
    scanner.scan(ip_address, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Ip Status:",scanner[ip_address].state())
    print (scanner[ip_address].all_protocols())
    print("Open Ports:", scanner[ip_address]['udp'].keys())
elif resp == "3":
    print("Nmap version:", scanner.nmap_version())
    scanner.scan(ip_address, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip Status:",scanner[ip_address].state())
    print (scanner[ip_address].all_protocols())
    print("Open Ports:", scanner[ip_address]['tcp'].keys())
    print("Open Ports:", scanner[ip_address]['udp'].keys())
elif resp >= "4":
    print("Please enter a valid option")