#include <fstream>
#include <iostream>
#include <string>
#include <tins/tins.h>

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

	if(data.substr(0,15)=="HTTP/1.0 200 OK"||data.substr(0,15)=="HTTP/1.1 200 OK")
	{
		size_t ptr=data.find("\r\n\r\n");

		if(ptr!=std::string::npos)
			save_to_file(data.substr(ptr+4,data.size()),name+".html");
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
