# Goal 
# Have students graph incoming packets by port using pypcap & matplotlib

# Resources
# https://pypi.python.org/pypi/pypcapfile
# https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/

# Check if root needed to install the packages below, if so use a VM for teaching
import dpkt
from dpkt.tcp import TCP
import matplotlib.pyplot as plt
import sys
import socket

def get_ports(filename, address):
	
	# returns a list of ports and list of sequence numbers from a pcap file
	f = open(filename, 'rb')
	pcap = dpkt.pcap.Reader(f)
	
	sequence_list = []
	dport_list = []
		
	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		
		# check the packet is TCP
		if type(ip.data) == TCP :
			tcp = ip.data
			# get the source IP address
			source_ip = socket.inet_ntoa(ip.src)
			print (source_ip)
			#raw_input()
			# if the ip address matches that of the specified source, 
			# append the time stamp and destination port to their respective lists
			if source_ip == address: 
				sequence_list.append(ts)
				dport_list.append(tcp.dport)
	f.close()
	#print dport_list
	return (sequence_list, dport_list)
	

def plot_graph(sequence_list, dport_list):
	# generates a graph of ports vs sequence numbers
	p1, = plt.plot(sequence_list, dport_list,  'b-')
	plt.title("Student Number")
	plt.xlabel('Time Stamp')
	plt.ylabel('Port Number')
	plt.show()
	
def main (filename, address):
	# invokes other functions
	sequence_list, dport_list = get_ports(filename, address)
	plot_graph(sequence_list, dport_list)
	
	
# THIS IS THE PART YOU ADD/REPLACE
if __name__ == "__main__":
    if len(sys.argv) < 3: # Check if at least 2 arguments (plus script name) are provided
        print("Usage: python PythonApplication1.py <pcap_filename> <ip_address>")
        print("Example: python PortGraph.py Networkcapture1.pcap 192.168.56.101")
        sys.exit(1) # Exit with an error code
    
    filename = sys.argv[1]
    address = sys.argv[2]
    
    main(filename, address)
# example usage:
# python PortGraph.py Networkcapture1.pcap 192.168.56.101
# python PortGraph.py Networkcapture4.pcap 192.168.56.102

	
