#!/usr/bin/python
#  http://bt3gl.github.io/black-hat-python-infinite-possibilities-with-the-scapy-module.html

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import pefile
import pprint
from scapy.all import *

#parser = PcapReader("test.pcap")
#
#for p in parser:
#	test=str(p.payload)
#	count=0
#	pos=0
#
#	while pos>=0:
#		pos=test.find("\x0d\x0a\x32\x30\x30\x30\x0d\x0a",pos)
#
#		if pos>0:
#			count+=1
#			pos+=8
#
#	if count>0:
#		print(test)



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

					if header["transfer-encoding"].strip()=="chunked":
						#print(":".join("{:02x}".format(ord(c)) for c in payload[start_pos:start_pos+6]))
						end_pos=payload.find("\r\n",start_pos)
						new_size=int(payload[start_pos:end_pos],16)
						start_pos=end_pos+2
						end_pos=start_pos+new_size
					else:
						end_pos=start_pos+int(header["content-length"])

					data=payload[start_pos:end_pos]
					end_pos+=1

					ret.append((streams[ii],header,data));

				except Exception as e:
					break
		except:
			pass

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
				#print("BEFORE "+str(packet_payload.find("\r\n2000\r\n")))
				#packet_payload=packet_payload.replace("\r\n2000\r\n","");
				#print("AFTER  "+str(packet_payload.find("\r\n2000\r\n")))
				#payload_chunked+=packet_payload
				#print("OVERALL"+str(payload_chunked.find("\r\n2000\r\n")))

		ret.append((ii,payload));
		#ret.append((ii,payload_chunked.replace("\r\n2000\r\n","").replace("\r\n20a0\r\n","")));

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