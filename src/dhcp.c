#include <stdio.h>
#include <net/ether.h>
#include <net/udp.h>
#include <net/ip.h>
#include <net/nic.h>
#include <net/dhcp.h>
#include <malloc.h>
#include <gmalloc.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <util/map.h>
#include <util/event.h>

#define MAX 		0xfffffffe 
#define DHCP_SESSION	"net.dhcp.sessiontable"


bool dhcp_init(NIC* nic) {
	if(!nic) 
		return false;

	Map* session_map = map_create(8, map_uint64_hash, map_uint64_equals, NULL);
	if(!session_map)
		return false;

	return nic_config_put(nic, DHCP_SESSION, (void*)(uintptr_t)session_map); 
}

bool distroy_dhcp_session(NIC* nic, uint32_t t_id) {
	Map* session_map = nic_config_get(nic, DHCP_SESSION);
	if(!session_map)
		return false;

	DHCPSession* dhcp_session = map_get(session_map, (void*)(uintptr_t)t_id);
	if(!dhcp_session)
		return false;

	if(!map_remove(session_map, (void*)(uintptr_t)t_id))
		return false;

	return true;
}

bool dhcp_process(Packet* _packet) {
	Packet* packet = _packet;
	if(!packet)
		return false;

	Map* session_map = nic_config_get(packet->nic, DHCP_SESSION);
	if(!session_map)
		return false;

	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) != ETHER_TYPE_IPv4) 
		return false;

	IP* ip = (IP*)ether->payload;
	if(ip->protocol != IP_PROTOCOL_UDP) 
		return false;

	UDP* udp = (UDP*)ip->body;
	if(udp->source != endian16(DHCP_SERVER_PORT)) 
		return false;

	DHCP* dhcp = (DHCP*)udp->body;
	uint32_t t_id = endian32(dhcp->transaction_id);

	DHCPOption* dop = (DHCPOption*)dhcp->options;

	DHCPSession* dhcp_session = map_get(session_map, (void*)(uintptr_t)t_id);
	if(!dhcp_session)
		return false;
	if(dhcp_session->transaction_id != t_id) 		
		return false;

	uint32_t your_ip = 0; 
	uint32_t gateway_ip = 0;

	switch (*(dop->data)) {
		case DHCP_TYPE_OFFER:
			your_ip = endian32(dhcp->your_ip);
			gateway_ip = endian32(dhcp->gateway_ip);

			dhcp_session->your_ip = your_ip;
			dhcp_session->gateway_ip = gateway_ip;
			
			if(dhcp_session->discover_timer_id && event_timer_remove(dhcp_session->discover_timer_id))
				dhcp_session->discover_timer_id = 0;

			dhcp_session->offered(packet->nic, t_id, your_ip, NULL); 
			break;
		case DHCP_TYPE_ACK:
			your_ip = dhcp_session->your_ip;
			printf("SSSSSSSSSSSSSSSSSSSSSS  %p \n\n", your_ip);

			//if(dhcp_session->request_timer_id && event_timer_remove(dhcp_session->request_timer_id))
		//		dhcp_session->request_timer_id = 0;

			printf("AAAAAAAAAAAAAAAAAAAA \n\n");
			dhcp_session->ack_received(packet->nic, t_id, your_ip, NULL); 
			break;
		default:
			return false;
	}

	return true;
}

bool dhcp_discover(NIC* nic, uint32_t transaction_id) {
	printf("dhcp_discover  \n");
	Packet* packet = nic_alloc(nic, sizeof(Ether) + sizeof(IP) + sizeof(UDP) + sizeof(DHCP) + 26);
	if(!packet)
		return false;
	
	//ethernet
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	ether->dmac = endian48(0xffffffffffff);
	ether->smac = endian48(nic->mac);
	ether->type = endian16(ETHER_TYPE_IPv4);
		
	//ip
	IP* ip = (IP*)ether->payload;
	ip->ihl = endian8(5); //20
	ip->version = endian8(4);
	ip->ecn = endian8(0); 
	ip->dscp = endian8(0);
	//ip->id = endian16(ip_id);
	ip->flags_offset = 0x00;
	ip->ttl = endian8(IP_TTL);
	ip->protocol = endian8(IP_PROTOCOL_UDP);
	ip->source = endian32(0x00000000);
	ip->destination = endian32(0xffffffff);
	//length
	//id
	//checksum

	//udp
	UDP* udp = (UDP*)ip->body;
	udp->source = endian16(0x0044);
	udp->destination = endian16(0x0043);
	//dhcp
	DHCP* dhcp = (DHCP*)udp->body;
	dhcp->op_code = endian8(0x0001);
	dhcp->hw_type = endian8(0x0001);
	dhcp->hw_length = endian8(6);
	dhcp->hops = endian8(0x0000);
	dhcp->transaction_id = endian32(transaction_id);
	//second
	dhcp->flags = endian8(0x0000);
	dhcp->client_ip = endian32(0x00000000);
	dhcp->your_ip = endian32(0x00000000);
	dhcp->server_ip = endian32(0x00000000);
	dhcp->gateway_ip = endian32(0x00000000);
	dhcp->client_hw_addr = endian64((nic->mac)<<16);
	dhcp->client_hw_addr_padding = endian64(0);
	//file name 
	//server name
	dhcp->magic_cookie = endian32(DHCP_MAGICCOOKIE); 

	//dhcp option for message_type
	DHCPOption* message_type =  (DHCPOption*)dhcp->options;
	message_type->code = endian8(DHCP_OPTION_MESSAGE_TYPE);
	message_type->length = 0x01;
	*(message_type->data) = DHCP_TYPE_DISCOVER;

	DHCPOption* client_identifier = (DHCPOption*)(((message_type->data) + message_type->length));
	client_identifier->code = endian8(DHCP_OPTION_CLIENT_IDENTIFIER);
	client_identifier->length = 0x07;
	*(client_identifier->data) = DHCP_TYPE_DISCOVER;
	*(uint16_t*)((client_identifier->data) + 1) = endian16((nic->mac)>>32);
	*(uint32_t*)((client_identifier->data) + 3) = endian32(*(uint32_t*)(&(nic->mac)));


	DHCPOption* requested_ip = (DHCPOption*)(((client_identifier->data) + 0x07));
	requested_ip->code = endian8(DHCP_OPTION_REQUESTED_IP_ADDRESS);
	requested_ip->length = endian8(0x04);
	*(uint32_t*)((requested_ip->data)) = endian32(0);

	DHCPOption* parameter_request = (DHCPOption*)(((requested_ip->data) + 0x04));
	parameter_request -> code = endian8(DHCP_OPTION_PARAMETER_REQUEST_LIST); 
	parameter_request -> length= endian8(0x03);
	*(parameter_request->data) = DHCP_OPTION_SUBNETMASK;
	*((parameter_request->data) + 1) = DHCP_OPTION_ROUTERADDRESS;
	*((parameter_request->data) + 2) = DHCP_OPTION_DOMAIN_NAME;


	DHCPOption* end = (DHCPOption*)(((parameter_request->data) + 0x03));
	end->code = endian8(DHCP_OPTION_END);

	udp_pack(packet, sizeof(DHCP) + 26);
	nic_output(packet->nic, packet);

	return true;
}

uint32_t dhcp_create_session(NIC* nic, CallFunc discovered, CallFunc offered, CallFunc ack_received, void* context) {
	bool dhcp_timercallback(void* context) {
		DHCPSession* session = context;
		static int discover_count = 0;
		printf("test context: %p", context);
		bool callback = session->discovered(session->nic, session->transaction_id, 0, NULL);

		if(callback && (discover_count<=5)) {
			printf("dhcp_timer!!! %d \n", discover_count);
			dhcp_discover(session->nic, session->transaction_id);
			discover_count++;
			printf("dhcp_timeout count %d \n", discover_count);
			return true;
		} else {
			printf("dhcp_timout \n");
			discover_count=0;
			return false;
		}
		return true;
	}

	Map* session_map = nic_config_get(nic, DHCP_SESSION);
	if(!session_map) 
		return 0;
	DHCPSession* dhcp_session = (DHCPSession*)gmalloc(sizeof(DHCPSession));
	if(!dhcp_session) 
		return 0;

	uint64_t _id = 0;
	uint32_t* id = (uint32_t*)&_id; 
	asm volatile("rdtsc" : "=a"(id[0]), "=d"(id[1]));
	uint32_t transaction_id = (_id % MAX) + 3;

	while(map_get(session_map, (void*)(uintptr_t)transaction_id)) {
		asm volatile("rdtsc" : "=a"(id[0]), "=d"(id[1]));
		transaction_id = (_id % MAX) + 3;
	}

	map_put(session_map, (void*)(uintptr_t)transaction_id, dhcp_session);

	dhcp_session->discovered = discovered;
	dhcp_session->offered = offered;
	dhcp_session->ack_received = ack_received;
	dhcp_session->context = context;
	dhcp_session->transaction_id = transaction_id;
	dhcp_session->nic = nic;
	dhcp_discover(nic, transaction_id);

	uint64_t timer_id = event_timer_add(dhcp_timercallback, dhcp_session, 5000000, 5000000);
	printf("timer %d\n", timer_id);
	dhcp_session->discover_timer_id = timer_id;
	return transaction_id;
}

bool dhcp_request(NIC* nic, uint32_t key) {
	Map* session_map = nic_config_get(nic, DHCP_SESSION);
	if(!session_map)
		return false;

	DHCPSession* dhcp_session = map_get(session_map, (void*)(uintptr_t)key);
	if(!dhcp_session)
		return false;

	Packet* packet = nic_alloc(nic, sizeof(Ether) + sizeof(IP) + sizeof(UDP) + sizeof(DHCP));
	if(!packet)
		return false;

	Ether* ether = (Ether*)(packet->buffer + packet->start);
	ether->dmac = endian48(0xffffffffffff);
	ether->smac = endian48(nic->mac);
	ether->type = endian16(ETHER_TYPE_IPv4);
		
	IP* ip = (IP*)ether->payload;
	ip->ihl = endian8(5); //20
	ip->version = endian8(4);
	ip->ecn = endian8(0); 
	ip->dscp = endian8(0);

	//ip->id = endian16(ip_id);
	ip->flags_offset = 0x00;
	ip->ttl = endian8(IP_TTL);
	ip->protocol = endian8(IP_PROTOCOL_UDP);
	ip->source = endian32(0x010101fe);
	ip->destination = endian32(0xffffffff);
	//length
	//id
	//checksum

	UDP* udp = (UDP*)ip->body;
	udp->source = endian16(0x0044);
	udp->destination = endian16(0x0043);

	DHCP* dhcp = (DHCP*)udp->body;
	dhcp-> op_code = endian8(0x0001);
	dhcp-> hw_type = endian8(0x0001);
	dhcp-> hw_length = endian8(6);
	//TODO: calculate hops
	dhcp-> hops = endian8(0x0000);

	//transactionId
	//second
	dhcp-> transaction_id= endian32(dhcp_session->transaction_id);
	dhcp-> flags = endian8(0x0000);

	dhcp-> client_ip= endian32(0x00000000);
	dhcp-> your_ip= endian32(0x00000000);
	dhcp-> server_ip= endian32(0x00000000);
	dhcp-> gateway_ip = endian32(dhcp_session->gateway_ip);

	dhcp-> client_hw_addr = endian64((nic->mac)<<16);
	dhcp-> client_hw_addr_padding = endian64(0);
	dhcp-> magic_cookie = endian32(DHCP_MAGICCOOKIE); 

	//dhcp option for message_type
	DHCPOption* message_type =  (DHCPOption*)dhcp->options;
	message_type->code = endian8(DHCP_OPTION_MESSAGE_TYPE);
	message_type->length = 0x01;
	*(message_type->data) = DHCP_TYPE_REQUEST;

	DHCPOption* client_identifier = (DHCPOption*)(((message_type->data) + 0x01));
	client_identifier->code = endian8(DHCP_OPTION_CLIENT_IDENTIFIER);
	client_identifier->length = 0x07;
	*(client_identifier->data) = 0x01;
	*(uint16_t*)((client_identifier->data) + 1) = endian16((nic->mac)>>32);
	*(uint32_t*)((client_identifier->data) + 3) = endian32(*(uint32_t*)(&(nic->mac)));


	DHCPOption* requested_ip = (DHCPOption*)(((client_identifier->data) + 0x07));
	requested_ip->code = endian8(DHCP_OPTION_REQUESTED_IP_ADDRESS);
	requested_ip->length = endian8(0x04);
	*(uint32_t*)((requested_ip->data)) = endian32(dhcp_session->your_ip);

	DHCPOption* parameter_request = (DHCPOption*)(((requested_ip->data) + 0x04));
	parameter_request -> code = endian8(DHCP_OPTION_PARAMETER_REQUEST_LIST); 
	parameter_request -> length= endian8(0x03);
	*(parameter_request->data) = DHCP_OPTION_SUBNETMASK;
	*((parameter_request->data) + 1) = DHCP_OPTION_ROUTERADDRESS;
	*((parameter_request->data) + 2) = DHCP_OPTION_DOMAIN_NAME;

	DHCPOption* end = (DHCPOption*)(((parameter_request->data) + 0x03));
	end->code = endian8(DHCP_OPTION_END);

	udp_pack(packet, sizeof(DHCP) + 26);
	nic_output(packet->nic, packet);

	return true;
} 

bool dhcp_bound(NIC* nic, uint32_t key) {
	bool dhcp_resend_callback(void* context) {
		DHCPSession* session = context;
		static int discover_count = 0;

		if(discover_count<=5) {
			printf("dhcp_request again!!! %d \n", discover_count);
			dhcp_request(session->nic, session->transaction_id);
			discover_count++;
			return true;
		} else {
			printf("dhcp_request over \n");
			discover_count=0;
			return false;
		}
		return true;
	}

	Map* session_map = nic_config_get(nic, DHCP_SESSION);
	if(!session_map)
		return false;

	DHCPSession* dhcp_session = map_get(session_map, (void*)(uintptr_t)key);
	if(!dhcp_session)
		return false;

 	uint64_t timer_id = event_timer_add(dhcp_resend_callback, dhcp_session, 5000000, 5000000);
	dhcp_session->request_timer_id = timer_id;
	
	return true;
}

