#!/usr/bin/python
#  http://bt3gl.github.io/black-hat-python-infinite-possibilities-with-the-scapy-module.html

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import pefile
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

					ret.append((streams[ii],header,data));

				except Exception as e:
					break
		except:
			pass

	return ret

#returns [(stream,pefile,exe)]
def get_pefile(streams):
	ret=[]

	for ii in range(0,len(streams)):
		payload=streams[ii][1]

		try:
			pos=0
			lookups=["MZ","ZM"]

			for lu in lookups:
				while True:
					pos=payload.index(lu,pos)
					exe=payload[pos:]
					pe=pefile.PE(data=exe)
					pos+=len(lu)
					ret.append((streams[ii],pe,exe))
		except:
			pass

	return ret

def print_stream_flow(stream):
	print(stream[0]+" "+str(len(stream[1]))+" bytes")

def print_streams_flow(streams):
	for ii in range(0,len(streams)):
		print_stream_flow(streams[ii])

def save_streams(streams,out):
	count=0

	for ii in range(0,len(streams)):
		file=open(out+"/"+str(count)+".raw",'w')
		file.write(streams[ii][1])
		file.close()
		count+=1

def save_stream_pefiles(streams,out):
	count=0

	for ii in streams:
		file=open(out+"/"+str(count)+".exe",'w')
		file.write(ii[2])
		file.close()
		count+=1

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

#print_streams_flow(streams)
#save_streams(streams,"out")

pefiles=get_pefile(streams)
for ii in pefiles:
	print_stream_flow(ii[0])
	print(str(ii[1]))
	print("")
save_stream_pefiles(pefiles,"out")

#http_https=get_http_https(streams)
#for ii in http_https:
#	print_stream_flow(ii[0])
#	for jj in range(1,3):
#		print(str(ii[jj]))
#	print("")
