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
#include <util/list.h>
#include <string.h>

#define MAX 		0xfffffffe 
#define DHCP_SESSION	"net.dhcp.sessiontable"

#include <errno.h>

bool dhcp_request(DHCPSession* dhcp_session) {
	if(!dhcp_session) {
		errno = DHCP_ERROR_NO_SESSION;
		return false;
	}

	NIC* nic = dhcp_session->nic;
	uint32_t transaction_id = dhcp_session->transaction_id;

	if(!nic) {
		errno = DHCP_ERROR_NO_NIC;
		return false; 
	}
	
	if(!transaction_id) {
		errno = DHCP_ERROR_TID;
		return false;
	}

	Packet* packet = nic_alloc(nic, sizeof(Ether) + sizeof(IP) + sizeof(UDP) + sizeof(DHCP) + 40);
	if(!packet) {
		errno = DHCP_ERROR_NO_PACKET;
		return false;
	}

	memset(packet->buffer + packet->start, 0, sizeof(Ether) + sizeof(IP) + sizeof(UDP) + sizeof(DHCP) + 40);

	Ether* ether = (Ether*)(packet->buffer + packet->start);
	ether->dmac = endian48(0xffffffffffff);
	ether->smac = endian48(nic->mac);
	ether->type = endian16(ETHER_TYPE_IPv4);
		
	IP* ip = (IP*)ether->payload;
	ip->ihl = endian8(5); 
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
	dhcp-> op = endian8(0x0001);
	dhcp-> htype = endian8(0x0001);
	dhcp-> hlen = endian8(6);
	//TODO: calculate hops
	dhcp-> hops = endian8(0x0000);

	//transactionId
	//second
	dhcp->xid = endian32(dhcp_session->transaction_id);
	dhcp->flags = endian8(0x0);

	dhcp->ciaddr = endian32(0x00000000);
	dhcp->yiaddr = endian32(0x00000000);
	dhcp->siaddr = endian32(0x00000000);
	dhcp->giaddr = endian32(dhcp_session->gateway_ip);

	*dhcp->chaddr = endian48(nic->mac);

	dhcp->magic_cookie = endian32(DHCP_MAGICCOOKIE); 
//
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



	DHCPOption* dhcp_server = (DHCPOption*)(((client_identifier->data) + 0x07));
	dhcp_server -> code = endian8(DHCP_OPTION_SEVER_IDENTIFIER);
	dhcp_server -> length = endian8(0x04); 
	*(uint32_t*)((dhcp_server->data)) = endian32(0x0a000003);




	DHCPOption* requested_ip = (DHCPOption*)(((dhcp_server->data) + 0x04));
	requested_ip->code = endian8(DHCP_OPTION_REQUESTED_IP_ADDRESS);
	requested_ip->length = endian8(0x04);
	*(uint32_t*)((requested_ip->data)) = endian32(dhcp_session->your_ip);



	


	DHCPOption* host_name = (DHCPOption*)(((requested_ip->data) + 0x04));
	host_name -> code = endian8(DHCP_OPTION_HOST_NAME); 
	host_name -> length = endian8(0x04); 
	*(uint32_t*)((host_name->data)) = endian32(0x504b4c42);

	DHCPOption* parameter_request = (DHCPOption*)(((host_name->data) + 0x04));
	parameter_request -> code = endian8(DHCP_OPTION_PARAMETER_REQUEST_LIST); 
	parameter_request -> length= endian8(0x03);
	*(parameter_request->data) = DHCP_OPTION_SUBNETMASK;
	*((parameter_request->data) + 1) = DHCP_OPTION_ROUTERADDRESS;
	*((parameter_request->data) + 2) = DHCP_OPTION_DOMAIN_NAME;

	DHCPOption* end = (DHCPOption*)(((parameter_request->data) + 0x03));
	end->code = endian8(DHCP_OPTION_END);

	udp_pack(packet, sizeof(DHCP) + 40);
	//udp_pack(packet, sizeof(DHCP) + 32);
	if(!nic_output(packet->nic, packet)) {
		errno = DHCP_ERROR_REQUEST_FAIL;
		return false;
	}

	printf("DHCP request packet sent\n");
	return true;
} 

bool dhcp_bound(NIC* nic, uint32_t key) {
	bool dhcp_resend_callback(void* context) {
		DHCPSession* session = context;
		dhcp_request(session);
		return false;
	}

	Map* session_map = nic_config_get(nic, DHCP_SESSION);
	if(!session_map) {
		errno = DHCP_ERROR_NO_MAP;
		return false;
	}

	DHCPSession* dhcp_session = map_get(session_map, (void*)(uintptr_t)key);
	if(!dhcp_session) {
		errno = DHCP_ERROR_NO_SESSION;
		return false;
	}

 	uint64_t timer_id = event_timer_add(dhcp_resend_callback, dhcp_session, 60000000, 1800000000);
	dhcp_session->request_timer_id = timer_id;
	
	return true;
}


bool dhcp_init(NIC* nic) {
	if(!nic) {
		errno = DHCP_ERROR_NO_NIC;
		return false;
	}

	Map* session_map = map_create(8, map_uint64_hash, map_uint64_equals, NULL);
	if(!session_map) {
		errno = DHCP_ERROR_NO_MAP;
		return false;
	}

	if(!nic_config_put(nic, DHCP_SESSION, (void*)(uintptr_t)session_map)) { 
		map_destroy(session_map);	
		errno = DHCP_ERROR_NIC_CONFIG_FAIL;
		return false;
	}

	return true;
}

static bool dhcp_distroy_session(NIC* nic, uint32_t t_id) {
	Map* session_map = nic_config_get(nic, DHCP_SESSION);
	if(!session_map) {
		errno = DHCP_ERROR_NO_MAP;
		return false;
	}

	DHCPSession* dhcp_session = map_get(session_map, (void*)(uintptr_t)t_id);
	if(!dhcp_session) {
		errno = DHCP_ERROR_NO_SESSION;
		return false;
	}

	if(!map_remove(session_map, (void*)(uintptr_t)t_id)) {
		errno = DHCP_ERROR_MAP_REMOVE_FAIL;
		return false;
	}

	return true;
}

bool dhcp_process(Packet* _packet) {
	Packet* packet = _packet;
	if(!packet) {
		errno = DHCP_ERROR_NO_PACKET;
		return false;
	}

	Map* session_map = nic_config_get(packet->nic, DHCP_SESSION);
	if(!session_map) {
		errno = DHCP_ERROR_NO_SESSION;
		return false;
	}

	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) != ETHER_TYPE_IPv4) 
		return false;

	IP* ip = (IP*)ether->payload;
	if(ip->protocol != IP_PROTOCOL_UDP) 
		return false;

	UDP* udp = (UDP*)ip->body;
	if(udp->source != endian16(DHCP_SERVER_PORT)) {
		return false;
	}
	DHCP* dhcp = (DHCP*)udp->body;
	uint32_t t_id = endian32(dhcp->xid);

	DHCPOption* dop = (DHCPOption*)dhcp->options;

	DHCPSession* dhcp_session = map_get(session_map, (void*)(uintptr_t)t_id);
	if(!dhcp_session) {
		errno = DHCP_ERROR_NO_SESSION;
		return false;
	}
	if(dhcp_session->transaction_id != t_id) {
		errno = DHCP_ERROR_TID;
		return false;
	}

	uint32_t your_ip = 0; 
	uint32_t gateway_ip = 0;
	
	switch (*(dop->data)) {
		case DHCP_TYPE_OFFER:
			your_ip = endian32(dhcp->yiaddr);
			gateway_ip = endian32(dhcp->giaddr);

			if(dhcp_session->discover_timer_id && event_timer_remove(dhcp_session->discover_timer_id)) {
				dhcp_session->discover_timer_id = 0;
			}

			dhcp_session->your_ip = your_ip;
			dhcp_session->gateway_ip = gateway_ip;

			dhcp_request(dhcp_session);
			if(dhcp_session->offered)
				dhcp_session->offered(packet->nic, t_id, your_ip, dhcp_session->context); 
			break;
		case DHCP_TYPE_ACK:
			your_ip = dhcp_session->your_ip;

			if(dhcp_session->request_timer_id && event_timer_remove(dhcp_session->request_timer_id)) 
				dhcp_session->request_timer_id = 0;

			dhcp_bound(packet->nic, t_id);
			if(dhcp_session->acked)
				dhcp_session->acked(packet->nic, t_id, your_ip, dhcp_session->context); 
			nic_ip_add(packet->nic, your_ip);
			printf("DHCP ACK packet received\n");
			
			break;
		case DHCP_TYPE_NAK:
			dhcp_session->nic = NULL;
			dhcp_session->your_ip = 0; 		
			dhcp_session->gateway_ip = 0; 		
			dhcp_session->discover_timer_id = 0;
			dhcp_session->request_timer_id = 0;
			dhcp_session->discovered = NULL;
			dhcp_session->offered = NULL;
			dhcp_session->acked = NULL;
		 	break;
		default:
			return false;
	}

	return true;
}

bool dhcp_discover(DHCPSession* dhcp_session) {
	if(!dhcp_session) {
		errno = DHCP_ERROR_NO_SESSION;
		return false;
	}

	NIC* nic = dhcp_session->nic;
	if(!nic) {
		errno = DHCP_ERROR_NO_NIC;
		return false; 
	}
	
	uint32_t transaction_id = dhcp_session->transaction_id;
	if(!transaction_id) {
		errno = DHCP_ERROR_TID;
		return false;
	}

	Packet* packet = nic_alloc(nic, sizeof(Ether) + sizeof(IP) + sizeof(UDP) + sizeof(DHCP) + 32);
	if(!packet) {
		errno = DHCP_ERROR_NO_PACKET;
		return false;
	}

	memset(packet->buffer + packet->start, 0, sizeof(Ether) + sizeof(IP) + sizeof(UDP) + sizeof(DHCP) + 32);
	
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
	//TODO
//	ip->id = endian16(0);
	ip->flags_offset = 0x00;
	ip->ttl = endian8(IP_TTL);
	ip->protocol = endian8(IP_PROTOCOL_UDP);
	ip->source = endian32(0x00000000);
	ip->destination = endian32(0xffffffff);

	//udp
	UDP* udp = (UDP*)ip->body;
	udp->source = endian16(DHCP_CLIENT_PORT);
	udp->destination = endian16(DHCP_SERVER_PORT);
	
	//dhcp
	DHCP* dhcp = (DHCP*)udp->body;
	dhcp->op = endian8(0x0001);
	dhcp->htype = endian8(0x0001);
	dhcp->hlen = endian8(6);
	dhcp->hops = endian8(0x0000);
	dhcp->xid = endian32(transaction_id);
	//seconds
	dhcp->flags = endian8(0x0);
	dhcp->ciaddr = endian32(0x00000000);
	dhcp->yiaddr = endian32(0x00000000);
	dhcp->siaddr = endian32(0x00000000);
	dhcp->giaddr = endian32(0x00000000);
	
	*(dhcp->chaddr) = endian48(nic->mac);

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

	//udp_pack(packet, sizeof(DHCP) + 32);
	udp_pack(packet, sizeof(DHCP) + 32);
	if(!nic_output(packet->nic, packet)) {
		errno = DHCP_ERROR_DISCOVER_FAIL;	
	}

	printf("DHCP discover packet sent\n");
	return true;
}

uint32_t dhcp_lease_ip(NIC* nic, DHCPCallback offered, DHCPCallback acked, void* context) {
	bool dhcp_timercallback(void* context) {
		DHCPSession* session = context;
		static int discover_count = 0;

		if(discover_count <= 5) {
			printf("send dhcp again \n");
			dhcp_discover(session);
			discover_count++;
			return true;
		} else {
			dhcp_distroy_session(session->nic, session->transaction_id); 
			printf("dhcp failed \n");
			discover_count=0;
			return false;
		}
		return true;
	}

	if(!nic) {
		errno = DHCP_ERROR_NO_NIC;
		return 0;
	}

	Map* session_map = nic_config_get(nic, DHCP_SESSION);
	if(!session_map) {
		errno = DHCP_ERROR_NO_MAP;
		return 0;
	}

	DHCPSession* dhcp_session = (DHCPSession*)gmalloc(sizeof(DHCPSession));
	if(!dhcp_session) {
		errno = DHCP_ERROR_NO_SESSION;
		return 0;
	}

	uint64_t _id = 0;
	uint32_t* id = (uint32_t*)&_id; 

	asm volatile("rdtsc" : "=a"(id[0]), "=d"(id[1]));

	uint32_t transaction_id = (_id % MAX) + 3;
	while(map_get(session_map, (void*)(uintptr_t)transaction_id)) {
		asm volatile("rdtsc" : "=a"(id[0]), "=d"(id[1]));
		transaction_id = (_id % MAX) + 3;
	}

	map_put(session_map, (void*)(uintptr_t)transaction_id, dhcp_session);

	dhcp_session->offered = offered;
	dhcp_session->acked = acked;
	dhcp_session->context = context;
	dhcp_session->transaction_id = transaction_id;
	dhcp_session->nic = nic;
	dhcp_discover(dhcp_session);


	uint64_t timer_id = event_timer_add(dhcp_timercallback, dhcp_session, 5000000, 5000000);
	//printf("timer %d\n", timer_id);
	dhcp_session->discover_timer_id = timer_id;

	return transaction_id;
}


List* dhcp_ip_get_all(NIC* nic) {
	List* ip_list = list_create(NULL);
	if(!ip_list){
		return NULL;
	}

	Map* interfaces = nic_config_get(nic, NIC_ADDR_IPv4);
	if(!interfaces)
		return NULL;

	MapIterator iter;
	map_iterator_init(&iter, interfaces);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		list_add(ip_list, entry->key); 
	}

	return ip_list;
}
