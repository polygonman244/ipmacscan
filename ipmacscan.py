#MAC/IP address collector
#Requires either Npcap or Winpcap to be installed//
# //All versions of Nmap come with the Npcap/Winpcap dependency

#Jakob Davinroy; Cybersecurity Administrator
#July 11, 2024

from scapy.all import ARP, Ether, srp
import socket
import os
import sys

def get_mac_ip():
    #Get IP address of local machine
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    #Define network range to scan
    ip_range = local_ip.rsplit('.',1)[0] + '.1/24'

    #Create ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp

    #Send packet/Capture response
    result = srp(packet, timeout=3, verbose=0)[0]

    #Extract MAC and IP from the response and display results
    devices = []
    for sent, received in result:
        devices.append({'ip':received.psrc, 'mac':received.hwsrc})
    return devices

#Function for if the user wants to write the results to a file
def write_to_file(devices, filename):
    with open(filename, 'w') as file:
        for device in devices:
            file.write(f"IP Address:{device['ip']} - MAC Address:{device['mac']}\n")

#Function if the user only wants to display the output without writing to a file
def display_output(devices):
    for device in devices:
        print(f"IP Address:{device['ip']} - MAC Address:{device['mac']}\n")


if __name__ == '__main__':
    devices = get_mac_ip()

    #Give user a choice on if they want to write the results to a file or not
    user_choice = input("Do you want to write interface output to a file? (yes/no): ").strip().lower()
    if user_choice == 'yes':
        file_name = input("Enter the name of the output file [e.g., output.txt]: ").strip()
            #Conidtion if the user leaves the filename field blank
        if not file_name:
            file_name = "output.txt"
        directory = input("Enter the folder path to save the file to [e.g., /path/to/directory]: ").strip()
            #Condition if the user leaves the directory field blank
        if not directory:
            directory = os.getcwd()
        #Join the directory and filename to store full path of where the file is going
        full_path = os.path.join(directory, file_name)
        write_to_file(devices, full_path)
        print(f"Output written to {full_path}")
    elif user_choice != 'yes':
        display_output(devices)

    
    
