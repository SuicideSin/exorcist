#!/usr/bin/python
#  http://bt3gl.github.io/black-hat-python-infinite-possibilities-with-the-scapy-module.html

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import pefile
import pprint
from scapy.all import *

#returns [(stream,header,http_payload)]
def get_http_https(streams):
	ret=[]

	for ii in range(0,len(streams)):
		start_pos=0
		raw=streams[ii][1]+"\r\n\r\n"
		payload=""

		while raw.find("\r\n\r\n",start_pos)>=0:
			end_pos=raw.index("\r\n\r\n",start_pos)
			header=raw[start_pos:end_pos]
			end_pos+=4

			if len(header)>4 and header[0:4]=="HTTP":
				try:
					header=dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n',header))
					header=dict((key.lower(),value) for key,value in header.iteritems())

					if "transfer-encoding" in header and header["transfer-encoding"].strip()=="chunked":
						while raw.find("\r\n",end_pos)>=0:
							chunk_size=raw[end_pos:raw.find("\r\n",end_pos)]
							if len(chunk_size)>0:
								chunk_size=int(chunk_size,16)
								end_pos=raw.find("\r\n",end_pos)+2
								payload+=raw[end_pos:end_pos+chunk_size]
								end_pos+=chunk_size+2
							else:
								break
					elif "content-length" in header:
						size=int(header["content-length"].strip())
						payload=raw[end_pos:end_pos+size]
						end_pos+=size
				except Exception as error:
					pass

			start_pos=end_pos

		if len(payload)>0:
			ret.append((streams[ii],header,payload));

	return ret

def save_stream_http_https(streams,out):
	count=0

	for ii in streams:
		file=open(out+"/"+str(count)+".html",'w')
		file.write(ii[2])
		file.close()
		count+=1

#returns [(stream,pefile,exe)]
def get_pefile(streams):
	ret=[]

	for ii in range(0,len(streams)):
		payload=streams[ii][1]
		pos=0
		lookups=["MZ","ZM"]

		for lu in lookups:
			while payload.find(lu,pos)>=0:
				pos=payload.index(lu,pos)
				exe=payload[pos:]
				pos+=len(lu)

				try:
					pe=pefile.PE(data=exe)
					size=pe.sections[-1].PointerToRawData+pe.sections[-1].SizeOfRawData
					binary=exe[0:size]
					ret.append((streams[ii],pe,binary))
				except Exception as error:
					print(error)
					pass

	return ret

def save_stream_pefiles(streams,out):
	count=0

	for ii in streams:
		file=open(out+"/"+str(count)+".exe",'w')
		file.write(ii[2])
		file.close()
		count+=1

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

#returns [(stream,payload)]
def get_streams(filename):
	cap=rdpcap(filename)
	streams=cap.sessions()
	file_count=0

	ret=[]

	for ii in streams:
		payload=""
		payload_chunked=""
		for packet in streams[ii]:
			if TCP in packet and type(packet[TCP].payload)==Raw:
				packet_payload=str(packet[TCP].payload)
				payload+=packet_payload

		ret.append((ii,payload));

	return ret

#streams=get_streams("evidence01.pcap")
#streams=get_streams("attack-trace.pcap")
streams=get_streams("test.pcap")

#print_streams_flow(streams)
#save_streams(streams,"out")

#pefiles=get_pefile(streams)
#for ii in pefiles:
#	print_stream_flow(ii[0])
#	print(str(ii[1]))
#	print("")
#save_stream_pefiles(pefiles,"out")

http_https=get_http_https(streams)
#for ii in http_https:
#	for jj in range(1,3):
#		print(str(ii[jj]))
#	print("")
save_stream_http_https(http_https,"out")