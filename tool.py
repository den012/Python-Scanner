import nmap
import socket
import keyboard

def title():
    print("   _____  ______ ___     _   __ _   __ ______ ____     ______ ____   ____   __")
    print("  / ___/ / ____//   |   / | / // | / // ____// __ \   /_  __// __ \ / __ \ / /")
    print("  \__ \ / /    / /| |  /  |/ //  |/ // __/  / /_/ /    / /  / / / // / / // /")
    print("  __/ // /___ / ___ | / /|  // /|  // /___ / _, _/    / /  / /_/ // /_/ // /___")
    print("/____/ \____//_/  |_|/_/ |_//_/ |_//_____//_/ |_|    /_/   \____/ \____//_____/")
    print("\n<------------------------------------------------------------------------------------------------------------------------->")
    print("\n 1) nmap + ip + type(s for SYN ACK Scan/u for UDPS can/c for Comprehensive Scan)")
    print(" 2) portscan + host(ip) + port")
    print("                                             !!Press ESC to exit")

title()

scanner = nmap.PortScanner()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
run = True
while run: 
    command = input("> ")
    data = command.split(" ")
    ipAddr = data[1]
    if(data[0]=='nmap' and data[2]=='s'):
        print("\nNmap Version: ", scanner.nmap_version())
        scanner.scan(ipAddr, '1-1024', '-v -sS')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ipAddr].state)
        print(scanner[ipAddr].all_protocols())
        print("Open Ports: ", scanner[ipAddr]['tcp'].keys())
    elif(data[0]=='nmap' and data[2]=='u'):
        print("\nNmap Version: ", scanner.nmap_version())
        scanner.scan(ipAddr, '1-1024', '-v -sU')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ipAddr].state)
        print(scanner[ipAddr].all_protocols())
        print("Open Ports: ", scanner[ipAddr]['udp'].keys())
    elif(data[0]=='nmap' and data[2]=='c'):
        print("\nNmap Version: ", scanner.nmap_version())
        scanner.scan(ipAddr, '1-1024', '-v -sS -sV -A -O')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ipAddr].state)
        print(scanner[ipAddr].all_protocols())
        print("Open Ports: ", scanner[ipAddr]['tcp'].keys())
    elif(data[0]=='portscan'):
        host = data[1]
        port = int(data[2])
        if s.connect_ex((host, port)):
            print("The port is closed")
        else:
            print("The port is opened")
    else:
        print("Error!! Check your spelling")

