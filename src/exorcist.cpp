#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
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
	std::cout<<"\tSaved:\t\t"<<file<<std::endl;
}

void save_payload(const Tins::TCPStream::payload_type& payload,const std::string& name)
{
	save_to_file(std::string((char*)payload.data(),payload.size()),name+".raw");
}

void process_html(const Tins::RawPDU::payload_type& payload,const std::string& name)
{
	std::string data((char*)payload.data(),payload.size());
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

void process_nops(const Tins::RawPDU::payload_type& payload,const std::string& name)
{
	size_t count=0;

	for(size_t ii=0;ii<payload.size();++ii)
		if(payload[ii]==0x90)
			++count;

	std::cout<<"\tNOP Count:\t"<<count<<std::endl;
}

void process_windows_exe(const Tins::RawPDU::payload_type& payload,const std::string& name)
{
	std::string data((char*)payload.data(),payload.size());

	std::cout<<"\tContains MZ:\t"<<std::flush;
	if(data.find("MZ")!=std::string::npos)
		std::cout<<"true"<<std::endl;
	else
		std::cout<<"false"<<std::endl;

	std::cout<<"\tContains PE:\t"<<std::flush;
	if(data.find(std::string("PE\0\0",4))!=std::string::npos)
		std::cout<<"true"<<std::endl;
	else
		std::cout<<"false"<<std::endl;
}

void process_payload(const Tins::RawPDU::payload_type& payload,const std::string& name)
{
	std::string data((char*)payload.data(),payload.size());
	save_to_file(data,name+".raw");

	process_html(payload,name);
	process_nops(payload,name);
	process_windows_exe(payload,name);
}

bool follow_skip(Tins::TCPStream& stream)
{
	return true;
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

int main(int argc,char* argv[])
{
	try
	{
		if(argc<=1)
			throw std::runtime_error("Usage is: exorcist file.pcap");

		Tins::FileSniffer pcap(argv[1]);
		Tins::TCPStreamFollower follower;
		follower.follow_streams(pcap,follow_skip,follow);
	}
	catch(std::exception& error)
	{
		std::cout<<error.what()<<std::endl;
		return 1;
	}

	return 0;
}
