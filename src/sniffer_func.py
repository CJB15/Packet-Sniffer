from scapy.all import *
from docx import Document
import sys, os, ctypes

def packetsniff(GUI, filterString, printduring, savefile, maxpackets):
    print("Launched in sniffing mode.")

    try:
        is_admin = os.getuid() == 0 # Check if the user has administrator privilages on Linux
    except AttributeError: # If not on Linux it will throw error
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0 # And will check on windows if user if admin

    if not is_admin: # If not admin exit program early to avoid crash later on
        print("Error: Not in administrator mode, cannot sniff in this mode")
        sys.exit(1)

    print("Staring packet sniffing, press 'Ctrl + C' to end sniffing.")

    if filterString != None: # If a filter expression was provided
    	print('Filtering with BPF syntax expression "' + filterString + '".')

    #iFaceList = get_if_list() # Gets list of all interfaces
    #print("Sniffing over interfaces " + str(iFaceList) + ".")

    if maxpackets == None: # If a maximum number of packets wasn't provided then defualt to 0, this means it will sniff forver.
        maxpackets = 0

    if printduring: # If asked to print during sniffing
        printexpression = lambda x:x.summary()
    else: # If not then don't
        printexpression = ""

    packetcapture = sniff(iface = None, filter=filterString, prn=printexpression, count = maxpackets) # Begin packetsniffing with no set intertface (this defaults to sniffing all interfaces), with the provided filter expression, printing if set previously, for as many packets as specifed
    print("Packet sniffing stopped!")

    print(packetcapture) # Print details of the saved packet capture
    print("Saving packet log as " + savefile + ".pcap")
    wrpcap(savefile + ".pcap", packetcapture) # Save with the specifed file name as a pcap file.
