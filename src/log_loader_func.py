from scapy.all import *
import pandas as pd
from tqdm import tqdm
from docx import Document
import sys

def loadpcapfile(GUI, loadfile):
	print("Loading file " + loadfile + "...")
	try:
		packetcapture = rdpcap(loadfile) # Loads the specifed .pcap file
	except:
		print("Error: Invalid File loaded!") # If the file is invalid alert user and stop program
		sys.exit(1)
	print(packetcapture)
	return packetcapture # If successful then return pcap file data
        
def loadpacketdata(packetcapture, GUI):
	print("Loading packet data...")
	
	df_fields = ['src_ip'] + ['dst_ip'] + ['src_port'] + ['dst_port'] + ['protocol'] + ['time'] + ['ip_type'] # Estabisheds the filds for the pandas data frame
	
	log_df = pd.DataFrame(columns=df_fields) # Creates the data frame
	
	pbar = tqdm(total=len(packetcapture)) # Creates a loading bar, as this can take some time for larger .pcap files
	
	for packet in packetcapture: # Cycle though each packet in the .pcap file

		temp_ip_type = "---"
		temp_src_ip = "---"
		temp_dst_ip = "---"
		temp_src_port = "---"
		temp_dst_port = "---"
		temp_time =  "---"

		if (TCP in packet):
			temp_protocol = "TCP"
		elif (UDP in packet):
			temp_protocol = "UDP"
		else:
			temp_protocol = "Other"
            
		if (IP in packet): # If IPv4 then extract data from IP section

			temp_ip_type = "IP"

			try:
				temp_src_ip = packet[IP].src
				temp_dst_ip = packet[IP].dst
			except:
				temp_src_ip = "Unknown IP(s)"
				temp_dst_ip = "Unknown IP(s)"

			try:
				temp_src_port = packet[IP].sport
				temp_dst_port = packet[IP].dport
			except:
				temp_src_port = "Unknown Port(s)"
				temp_dst_port = "Unknown Port(s)"

			try:
				temp_time =  packet[IP].time
			except:
				temp_time =  "Unknown Time(s)"
            
		elif (IPv6 in packet): # If IPv6 then extract data from IPv6 section

			temp_ip_type = "IPv6"

			try:
				temp_src_ip = packet[IPv6].src
				temp_dst_ip = packet[IPv6].dst
			except:
				temp_src_ip = "Unknown IP(s)"
				temp_dst_ip = "Unknown IP(s)"

			try:
				temp_src_port = packet[IPv6].sport
				temp_dst_port = packet[IPv6].dport
			except:
				temp_src_port = "Unknown Port(s)"
				temp_dst_port = "Unknown Port(s)"

			try:
				temp_time =  packet[IPv6].time
			except:
				temp_time =  "Unknown Time(s)"

		else: # If not an IP packet then use unkown values
			temp_ip_type = "Not IP"
			temp_src_ip = "Unknown IP(s)"
			temp_dst_ip = "Unknown IP(s)"
			temp_src_port = "Unknown Port(s)"
			temp_dst_port = "Unknown Port(s)"
			temp_time =  "Unknown Time(s)"

		packet_data = { # Save data
			'src_ip': temp_src_ip, 
			'dst_ip': temp_dst_ip, 
			'src_port': temp_src_port, 
			'dst_port': temp_dst_port,
			'protocol': temp_protocol,
			'time': temp_time,
			'ip_type': temp_ip_type
		}
				    
		temp_df = pd.DataFrame([packet_data], index=[0]) # Create a new pandas datafame with the data as the one row
		log_df = pd.concat([log_df, temp_df]) # Add to the exising data frame

		pbar.update(1) # Progress loading bar
	pbar.close() # Close loading bar
	
	return log_df # Return the final data frame
	
