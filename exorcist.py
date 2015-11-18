#!/usr/bin/python
#  http://bt3gl.github.io/black-hat-python-infinite-possibilities-with-the-scapy-module.html

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.error import Scapy_Exception

#returns [(stream,header,http_payload)]
def get_http_https(streams):
	ret=[]

	for ii in range(0,len(streams)):
		start_pos=0

		try:
			streams[ii][1].index("\r\n\r\n")
			payload=streams[ii][1]+"\r\n\r\n"

			while True:
				try:
					end_pos=payload.index("\r\n\r\n",start_pos)

					header=payload[start_pos:end_pos]
					header=dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n',header))
					header=dict((key.lower(),value) for key,value in header.iteritems())

					start_pos=end_pos+4
					end_pos=start_pos+int(header["content-length"])

					data=payload[start_pos:end_pos]
					end_pos+=1

					ret.append((streams[ii][0],header,data));
				except Exception as e:
					break
		except:
			pass

	return ret

#returns [(stream,header,ftp_payload)]
def get_ftp(streams):
	for ii in range(0,len(streams)):
		payload=streams[ii][1]
		print(payload)

def print_streams(streams):
	for ii in range(0,len(streams)):
		print(streams[ii][0]+" "+str(len(streams[ii][1]))+" bytes")

def save_streams(streams,out):
	stream_count=0

	for ii in range(0,len(streams)):
		file=open(out+"/"+str(stream_count)+".raw",'w')
		file.write(streams[ii][1])
		file.close()
		stream_count+=1

#returns [(stream,payload)]
def get_streams(filename):
	cap=rdpcap(filename)
	streams=cap.sessions()
	file_count=0

	ret=[]

	for ii in streams:
		payload=""
		for packet in streams[ii]:
			try:
				payload+=str(packet[TCP].payload)
			except:
				continue
		ret.append((ii,payload));

	for ii in streams:
		payload=""
		for packet in streams[ii]:
			try:
				payload+=str(packet[UDP].payload)
			except:
				continue
		ret.append((ii,payload));

	return ret

#streams=get_streams("evidence01.pcap")
streams=get_streams("attack-trace.pcap")
#print_streams(streams)
save_streams(streams,"temp")

#for ii in get_http_https(streams):
#	for jj in range(0,3):
#		print(str(ii[jj])+"\n")

#get_ftp(streams)