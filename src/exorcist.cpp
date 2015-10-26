#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <tins/tins.h>

std::string to_lower(std::string str)
{
	for(auto& ii:str)
		ii=tolower(ii);

	return str;
}

void save_to_file(const std::string& data,const std::string& file)
{
	std::ofstream ostr(file);
	ostr<<data;
	ostr.close();
	std::cout<<"Saved: "<<file<<std::endl;
}

void save_payload(const Tins::TCPStream::payload_type& payload,const std::string& name)
{
	save_to_file(std::string((char*)payload.data(),payload.size()),name+".raw");
}

void process_payload(const Tins::RawPDU::payload_type& payload,const std::string& name)
{
	std::string data((char*)payload.data(),payload.size());
	save_to_file(data,name+".raw");
	size_t count=0;
	size_t ptr=0;

	while(true)
	{
		bool found=false;

		if(data.substr(ptr,15)=="HTTP/1.0 200 OK"||data.substr(ptr,15)=="HTTP/1.1 200 OK")
		{
			size_t cl_ptr=to_lower(data).find("content-length:",ptr);
			size_t header_end=data.find("\r\n\r\n",ptr);

			if(cl_ptr!=std::string::npos&&header_end!=std::string::npos)
			{
				std::istringstream istr(data.substr(cl_ptr+15,data.size()));
				size_t html_size=0;

				if((istr>>html_size)&&html_size>0&&html_size<data.size())
				{
					save_to_file(data.substr(header_end+4,html_size),name+"_"+std::to_string(count)+".html");
					ptr+=header_end+4+html_size;
					++count;
					found=true;
				}
			}
		}

		if(!found||ptr>=data.size())
			break;
	}
}

bool follow(Tins::TCPStream& stream)
{
	const Tins::RawPDU::payload_type& server=stream.server_payload();
	std::string server_name="out/server0"+std::to_string(stream.id());
	std::cout<<server.size()<<"\t"<<stream.stream_info().server_addr.to_string()<<":"<<stream.stream_info().server_port<<"->"<<stream.stream_info().client_addr.to_string()<<":"<<stream.stream_info().client_port<<std::endl;
	process_payload(server,server_name);

	const Tins::RawPDU::payload_type& client=stream.client_payload();
	std::string client_name="out/client0"+std::to_string(stream.id());
	std::cout<<client.size()<<"\t"<<stream.stream_info().server_addr.to_string()<<":"<<stream.stream_info().server_port<<"<-"<<stream.stream_info().client_addr.to_string()<<":"<<stream.stream_info().client_port<<std::endl;
	process_payload(client,client_name);

	return true;
}

int main()
{
	Tins::FileSniffer pcap("evidence01.pcap");
	Tins::TCPStreamFollower follower;
	follower.follow_streams(pcap,follow);
	return 0;
}
