#!/user/bin/python3
import nmap

scanner = nmap.PortScanner()

print("Simple Nmap automation tool")
print("----------------------------------------------")
ip_addr = input("Enter the IP Address you would like to scan: ")
print(" The value of the IP you entered was: ", ip_addr)
type(ip_addr)

res = input(""" \nPlease enter the type of scan you would like to run
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan 
                4) Regular Scan
                5) OS Search
                6) Ping Scan
                \n""")
print('You have selected option: ', res)


if res == '1': #SYN ACK
    print("Nmap version: ", scanner.nmap_version())
    #scan(ip, ports, verbose and scan type)
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print("Scan Info: ", scanner.scaninfo())
    print("IP status: ", scanner[ip_addr].state())
    print("Current Protocol in Use: " , scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['tcp'].keys())

elif res == '2': #UDP  
    print("Nmap version: ", scanner.nmap_version())
    #scan(ip, ports, verbose and scan type)
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print("Scan Info: ", scanner.scaninfo())
    print("IP status: ", scanner[ip_addr].state())
    print("Current Protocol in Use: " , scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['udp'].keys())

elif res == '3':
    print("Nmap version: ", scanner.nmap_version())
    #scan(ip, ports, verbose and scan type)
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print("Scan Info: ", scanner.scaninfo())
    print("IP status: ", scanner[ip_addr].state())
    print("Current Protocol in Use: " , scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['tcp'].keys())   

elif res == '4':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr)
    print("Scan Info: ", scanner.scaninfo())
    print("IP status: ", scanner[ip_addr].state())
    print("Current Protocol in Use: " , scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['tcp'].keys()) 

elif res == '5':
    oper_sys = scanner.scan(ip_addr, arguments="-O")['scan'][ip_addr]['osmatch'][0]
    print(oper_sys)

elif res == '6':
    scanner.scan(hosts=ip_addr, arguments='-n -sP -PE -PA21,23,8-,3389')
    hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
    for host, status in hosts_list:
            print('{0}:{1}'.format(host, status))
else: 
    print("Enter a valid option")