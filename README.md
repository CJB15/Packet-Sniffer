Name: 'Basic Packet Sniffer'
Version: '1.0'
Description: 'Basic pakcet sniffer with graphical chat and document generating functionality.'
Author: 'Cameron Bell'
Email: 'cjb15@hw.ac.uk'

User Guide:

A copy of the user guide can be found in the project write up.


1 – Overview

This tool is used via a command line, by using a command to run the ‘Main.py’ python script. 

In the following guide the given commands were written for a Windows machine command line running Python 3.10.2, which uses the ‘python’ command. 
The commands for other systems such as Linux machines may differ, such as using ‘python3’ instead. 

Administrator privileges are required for some features of this tool as such the command line should be launched in administrator mode or each command should be prefixed with sudo (if on Linux).
 
An internet connection is also required to use certain features.


2 – Setup

First python must be installed as this program is a python script (https://www.python.org/downloads/).

Then if being set up on Windows then Npcap must be installed to allow it to work (https://npcap.com/#download), otherwise if on Linux this can be ignored.

Then to install all the required python packages the user should open the project folder in the command line and use the requirements.txt file to install every specified package.  The requirements text file contains the name of every required package. An example of this being done with PIP is:
python -m pip install -r requirements.txt

Once this is done they can access the scripts in the ‘src’ folder


3 – Sniffing Mode

Sniffing mode allows the user to begin sniffing packets on the network, it must be ruin in administrator mode to function.

To launch the program in sniffing mode use the ‘-s’ argument followed by the name of the pcap file to be saved afterwards:
python Main.py -s “Example”
This would begin sniffing until the user interrupts with ‘Crtl + C’ keys at which point the sniffing would end and would save the intercepted packets as ‘Example.pcap”.

The user can have the program print each pack intercepted in real time by including the ‘-p’ argument:
python Main.py -s “Example” -p

The user can have the program sniff until a specified amount of packets have been intercepted by including the -m command followed by a positive integer:
python Main.py -s “Example” -m 20
This would sniff until 20 packets had been intercepted.

The user can filter the packets that are recorded by the sniffer with the ‘-f’ argument followed by a string expression in the Berkeley Packet Filter (BPF) syntax format:
python Main.py -s “Example” -f “src host 51.11.122.226 and tcp”
This would only intercept packets that has ‘51.11.122.226’ as it’s source IP address and has tcp as its protocol.


4 – Loading Mode

Loading mode allows the user to load an existing pcap file to be processed.

To launch the program in loading mode use the ‘-l’ argument followed by the name/location of the pcap file to be loaded afterwards:
sudo python3 Main.py -l “Example.pcap”
This will then load and process the selected pcap file, it will then create a folder called “Example.pcap outputs”, here it will save some of the charts. During this process it will connect online to an IP lookup service, if there is no internet connection then this stage will be skipped, the IP maps and document will then be saved.

The user can set the maximum number of entries that will appear in the bar charts and document b using the ‘-m’ argument followed by a positive integer:
python Main.py -l “Example.pcap” -m 20
In this example the returned charts and document will only show the top 20 Addresses and ports in the charts/document.  If this is not set then it will default to 50 to ensure that the retuned charts/document are legible.

The user can specify an IP address to generate the charts/document on. Instead of showing a chart of all source IP addresses it will only count cases where the source IP sent packets to the specified IP address, vice versa for only counting destination addresses that received packets from the specified IP address. It is used with a ‘-i’ argument followed by an IP address:
python Main.py -l “Example.pcap” -i “10.0.2.4”
In this example the charts/map/document will only show information pertaining to the IP address “10.0.2.4”.

