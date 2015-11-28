#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import magic
import mimetypes
import os
from scapy.all import *
import sys

#returns [(session,carving,mime)]
def carve_http(streams):
	ret=[]

	for stream in streams:
		start_pos=0
		raw=stream[1]+"\r\n\r\n"
		carving=""
		mime=""
		header=""

		while raw.find("\r\n\r\n",start_pos)>=0:
			end_pos=raw.index("\r\n\r\n",start_pos)
			header=raw[start_pos:end_pos]
			end_pos+=4

			if len(header)>4 and header[0:4]=="HTTP":
				try:
					header=dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n',header))
					header=dict((key.lower(),value) for key,value in header.iteritems())
					if "content-type" in header:
						mime=str(header["content-type"].strip())
						if mime.find(";")>-1:
							mime=mime[0:mime.index(";")]

					if "transfer-encoding" in header and header["transfer-encoding"].strip()=="chunked":
						while raw.find("\r\n",end_pos)>=0:
							chunk_size=raw[end_pos:raw.find("\r\n",end_pos)]
							if len(chunk_size)>0:
								chunk_size=int(chunk_size,16)
								end_pos=raw.find("\r\n",end_pos)+2
								carving+=raw[end_pos:end_pos+chunk_size]
								end_pos+=chunk_size+2
							else:
								break
					elif "content-length" in header:
						size=int(header["content-length"].strip())
						carving=raw[end_pos:end_pos+size]
						end_pos+=size
				except:
					pass

				if len(carving)>0 and carving!="\r\n\r\n":
					ret.append((stream,carving,mime));

			start_pos=end_pos

	return ret

def save_carvings(carvings,out,count_start=0):
	count=count_start

	try:
		for carving in carvings:
			mime=carving[2]
			if mime=="":
				mime=magic.from_buffer(carving[1],mime=True)

			extension=str(mimetypes.guess_extension(mime))
			if mime=="text/javascript" or mime=="application/x-javascript":
				extension=".js"
			if mime=="text/html":
				extension=".html"
			if mime=="application/ocsp-response":
				extension=".ocsp"
			if mime=="image/x-icon":
				extension=".ico"
			if mime=="application/x-gzip":
				extension=".gz"
			if mime=="application/exe" or mime=="application/x-dosexec":
				extension=".exe"
			if mime=="application/pkix-crl":
				extension=".crl"
			if mime=="application/x-msdownload":
				extension=".dll"
			if mime[0:18]=="application/vnd.rn":
				extension=".rm"
			if extension==".jpe":
				extension=".jpg"
			if extension=="None" or extension=="":
				extension=".html"

			file_folder=str(carving[0][0])
			file_folder=file_folder.replace(" ","_")
			file_folder=file_folder.replace(">","TO")
			file_path=out+"/"+file_folder+"/"
			if not os.path.isdir(file_path):
				os.makedirs(file_path)
			print("\tSaving \""+file_path+str(count)+extension+"\"")
			file=open(file_path+str(count)+extension,'w')
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
		print("Usage: ./exorcist file.pcap ...")
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
