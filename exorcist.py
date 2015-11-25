#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import magic
import mimetypes
from scapy.all import *
import sys

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

def save_stream_http_https(streams,out,count_start=0):
	count=count_start

	try:
		for ii in streams:
			extension=".raw"

			try:
				with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
					mime=str(m.id_buffer(ii[2]))
					extension=str(mimetypes.guess_extension(mime))
					if extension=="None":
						if mime=="application/x-dosexec":
							extension=".exe"
						elif mime=="application/vnd.ms-cab-compressed":
							extension=".cab"
						elif mime=="application/gzip":
							extension=".gz"
						elif mime=="application/CDFV2-corrupt":
							extension=".doc"
						elif mime=="image/x-icon":
							extension=".ico"
						else:
							print("Unknown mime \""+mime+"\" "+str(count)+".raw")
							extension=".raw"
			except:
				pass

			file=open(out+"/"+str(count)+extension,'w')
			file.write(ii[2])
			file.close()
			count+=1
	except:
		raise Exception("Error saving files.")
	finally:
		return count

#returns [(stream,payload)]
def get_streams(filename):
	try:
		cap=rdpcap(filename)
		streams=cap.sessions()
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
	except:
		raise Exception("Error opening pcap \""+filename+"\".")

if __name__=="__main__":
	if len(sys.argv)<=1:
		print("Usage: ./exorcist file.pcap ...")
		exit(1)

	files_wrote=0

	for ii in range(1,len(sys.argv)):
		filename=str(sys.argv[ii])
		try:
			streams=get_streams(filename)
			http_https=get_http_https(streams)
			files_wrote=save_stream_http_https(http_https,"out",files_wrote)
		except Exception as error:
			print(error)
