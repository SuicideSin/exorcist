#!/usr/bin/python

import hashlib
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
from scapy.all import *
import sys

#returns [(session,carving)]
def carve_http(streams):
	ret=[]
	requests=[]

	for stream in streams:
		start_pos=0
		raw=stream[1]+"\r\n\r\n"
		carving=""
		header=""

		while raw.find("\r\n\r\n",start_pos)>=0:
			end_pos=raw.index("\r\n\r\n",start_pos)
			header=raw[start_pos:end_pos]
			end_pos+=4

			if header[:4]=="HTTP":
				try:
					header=dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n',header))
					header=dict((key.lower(),value) for key,value in header.iteritems())

					if "transfer-encoding" in header and header["transfer-encoding"].strip()=="chunked":
						while raw.find("\r\n",end_pos)>=0:
							chunk_size=raw[end_pos:raw.find("\r\n",end_pos)]

							if len(chunk_size)<=0:
								break

							chunk_size=int(chunk_size,16)
							end_pos=raw.find("\r\n",end_pos)+2
							carving+=raw[end_pos:end_pos+chunk_size]
							end_pos+=chunk_size+2

					elif "content-length" in header:
						size=int(header["content-length"].strip())
						carving=raw[end_pos:end_pos+size]
						end_pos+=size

				except:
					pass

				if len(carving)>0 and carving!="\r\n\r\n":
					ret.append((stream,carving))

			start_pos=end_pos

	return ret

#expects carvings in [(session,carving)]
def save_carvings(carvings,out,count_start=0):
	count=count_start

	try:
		for carving in carvings:
			file_folder=str(carving[0][0])
			file_folder=file_folder.replace(" ","_")
			file_folder=file_folder.replace(">","TO")
			file_path=out+"/"+file_folder+"/"

			if not os.path.isdir(file_path):
				os.makedirs(file_path)

			full_path=file_path+hashlib.sha1(carving[1]).hexdigest()
			print("\tSaving \""+full_path+"\"")
			file=open(full_path,'w')
			file.write(carving[1])
			file.close()
			count+=1

	except Exception as error:
		print(error)
		raise Exception("Error saving files.")

	finally:
		return count

#returns [(session,payload)]
def get_streams(filename):
	try:
		cap=rdpcap(filename)
		sessions=cap.sessions()
		ret=[]

		for session in sessions:
			payload=""
			payload_chunked=""

			for packet in sessions[session]:
				if TCP in packet and type(packet[TCP].payload)==Raw:
					packet_payload=str(packet[TCP].payload)
					payload+=packet_payload

			ret.append((session,payload));

		return ret

	except:
		raise Exception("Error opening pcap \""+filename+"\".")

if __name__=="__main__":
	if len(sys.argv)<=1:
		print("Usage: ./exorcist.py file.pcap ...")
		exit(1)

	files_wrote=0

	for ii in range(1,len(sys.argv)):
		filename=str(sys.argv[ii])
		print("Processing \""+filename+"\"")

		try:
			streams=get_streams(filename)
			carvings=carve_http(streams)
			files_wrote=save_carvings(carvings,"out/"+filename,files_wrote)

		except Exception as error:
			print(error)
