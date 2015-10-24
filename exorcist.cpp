#include <fstream>
#include <iostream>
#include <string>
#include <tins/tins.h>

void save_payload(const Tins::TCPStream::payload_type& payload,const std::string& file)
{
	std::string data((char*)payload.data(),payload.size());

	std::ofstream ostr(file);
	ostr<<data;
	ostr.close();

	std::cout<<"Saved: "<<file<<std::endl;
}

bool follow(Tins::TCPStream& stream)
{
	const Tins::RawPDU::payload_type& server=stream.server_payload();
	std::cout<<server.size()<<"\t"<<stream.stream_info().server_addr.to_string()<<":"<<stream.stream_info().server_port<<"->"<<stream.stream_info().client_addr.to_string()<<":"<<stream.stream_info().client_port<<std::endl;
	save_payload(server,"out/server0"+std::to_string(stream.id())+".out");

	const Tins::RawPDU::payload_type& client=stream.client_payload();
	std::cout<<client.size()<<"\t"<<stream.stream_info().server_addr.to_string()<<":"<<stream.stream_info().server_port<<"<-"<<stream.stream_info().client_addr.to_string()<<":"<<stream.stream_info().client_port<<std::endl;
	save_payload(client,"out/client0"+std::to_string(stream.id())+".out");

	return true;
}

int main()
{
	Tins::FileSniffer pcap("evidence01.pcap");
	Tins::TCPStreamFollower follower;
	follower.follow_streams(pcap,follow);
	return 0;
}
