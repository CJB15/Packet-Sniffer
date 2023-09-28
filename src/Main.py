import sys
import getopt

from log_loader_func import *
from output_gen_func import *
from sniffer_func import *

def main(argv): # Note: The developer guide in the dissertation explains some code sections better than the internal commentary
    savefile = None # Holds the name of the packet log file to be saved if one is generated
    loadfile = None # Holds the name of the packet log file to be loaded if one is to be processed
    
    GUI = False # Unused
    
    filterString = None # TODO
    printduring = False # If true then each packet is printed as it is sniffed
    
    ipadress = None # Holds the ip adress if data is being generated for one specific ip adresss
    maxpackets = None # Holds the maximum number of entries to be displayed in the charts/maps/document

    try:
        opts, args = getopt.getopt(argv, "hgf:ps:l:i:m:")#, ["savefile=", "loadfile="]) # Get the user inputed commands
    except getopt.GetoptError: # If invalid print error
        print("Command Error!")
        printhelp()
        sys.exit(0)

    for opt, arg in opts:
        if opt == "-h": # If entered then print the help and nothing else
        	printhelp()
        	sys.exit(0)
        if opt == "-g": # Unused
        	GUI = False
        if opt == "-f": # Used to enter the filter options for the sniffing function
        	filterString = arg
        if opt == "-p": # Flags the sniffer to print each packet as intercepted
        	printduring = True
        if opt == "-s": # Flags the program to launch the sniffing function, while specifing the name of the file to be saved
        	savefile = arg
        if opt == "-l": # Flags the program to launch the data procesing function, while specifing the name of the file to be loaded
        	loadfile = arg
        if opt == "-i": # Specifes a specific IP adress, the genereated report will only include data about this IP adress
        	ipadress = arg
        if opt == "-m": # Specifes the max amount of entreis to appear in the charts/maps/document and the max amount of packets to sniff
            try:
                if(int(arg) <= 0):
                    raise Exception()
            except:
                print("Invalid Max Number")
                sys.exit(1)
            
            maxpackets = int(arg)
            
    if (savefile != None): # If the user included -s then load the sniffing function
        packetsniff(GUI, filterString, printduring, savefile, maxpackets) # Runs the packet sniffing function
    elif (loadfile != None): # If the user included -l then load the data processing function
        packetcapture = loadpcapfile(GUI, loadfile) # Runs the load pcap file function
        log_df = loadpacketdata(packetcapture, GUI) # Runs the function to load the data from the pcap file into a pandas data frame
        graphgen(log_df, GUI, loadfile, ipadress, maxpackets) # Processes the pandas data frame into charts/maps/document
    else:
        printhelp() # If neither -s or -l were enterd then print help message
        
    #Program then ends
            
def printhelp(): # Help mesage to explain functionality, TODO rewrite to better explain how it works
    print("-h               Prints a list of all commands, not running the program.")
    print("")
    print('-s "filename"    Starts in sniffing mode, saving the resulting packet log.')
    print('-l "filename"    Starts the program in packet analysis mode loading an existing .pcap file.')
    print("Use -s to sniff and save a .pcap file, then use -l to load and generate the packet analysis.")
    print("")
    print('-f "filter"      Specifes the filters to be applied to the sniffing process, uses Berkeley Packet Filter syntax. (For -s)')
    print("-p               Flags to print the packets as they are intercepted. (For -s)")
    print("")
    print('-i "IP adress"   Generates a report about only packets sent to or from this IP adress, giving more information than the normal report. (For -l) ')
    print("")
    print('-m "Number"      In sniff mode sets the max amopunt of packets to intercept before ending, no value sniffs infinitly.  (For -s) ')
    print('                 In load mode sets the maximum number of enteries in the charts and document, no value defaults to 50. (For -l) ')
   
    print("")

if __name__ == "__main__":
    main(sys.argv[1:])
