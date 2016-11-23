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
#include <errno.h>

#define MAX 		0xfffffffe 
#define DHCP_SESSION	"net.dhcp.sessiontable"
#define HOST_NAME 	0x504b4c42 		//PKLB

void dhcp_bound_state(DHCPState *state);
void dhcp_init_state(DHCPState *state);

void dhcp_state_init(DHCPState *state) {
	state->next_state = NULL;
	state->lease_timer = 0;
}

static bool dhcp_request(DHCPSession* dhcp_session) {
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

	ip->id = endian16(0);
	ip->flags_offset = 0x00;
	ip->ttl = endian8(IP_TTL);
	ip->protocol = endian8(IP_PROTOCOL_UDP);
	ip->source = endian32(0x00000000);
	ip->destination = endian32(0xffffffff);

	UDP* udp = (UDP*)ip->body;
	udp->source = endian16(0x0044);
	udp->destination = endian16(0x0043);

	DHCP* dhcp = (DHCP*)udp->body;
	dhcp->op = endian8(0x0001);
	dhcp->htype = endian8(0x0001);
	dhcp->hlen = endian8(6);
	//TODO: calculate hops
	dhcp->hops = endian8(0x0000);

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
	
	DHCPOption* message_type =  (DHCPOption*)dhcp->options;
	message_type->code = endian8(DHCP_OPTION_MESSAGE_TYPE);
	message_type->length = DHCP_OPTION_MESSAGE_TYPE_LENGTH;
	*(message_type->data) = DHCP_TYPE_REQUEST;

	DHCPOption* client_identifier = (DHCPOption*)((message_type->data) + message_type->length);
	client_identifier->code = endian8(DHCP_OPTION_CLIENT_IDENTIFIER);
	client_identifier->length = DHCP_OPTION_CLIENT_IDENTIFIER_LENGTH;
	*(client_identifier->data) = 0x01;
	*(uint16_t*)((client_identifier->data) + 1) = endian16((nic->mac)>>32);
	*(uint32_t*)((client_identifier->data) + 3) = endian32(*(uint32_t*)(&(nic->mac)));
	DHCPOption* requested_ip;
	if(dhcp_session->server_ip == 0) {
		requested_ip = (DHCPOption*)((client_identifier->data) + client_identifier->length);
	} else {
		DHCPOption* dhcp_server = (DHCPOption*)((client_identifier->data) + client_identifier->length);
		dhcp_server->code = endian8(DHCP_OPTION_SEVER_IDENTIFIER);
		dhcp_server->length = endian8(DHCP_OPTION_SEVER_IDENTIFIER_LENGTH); 
		*(uint32_t*)((dhcp_server->data)) = endian32(dhcp_session->server_ip);
		requested_ip = (DHCPOption*)((dhcp_server->data) + dhcp_server->length);
	}
	requested_ip->code = endian8(DHCP_OPTION_REQUESTED_IP_ADDRESS);
	requested_ip->length = endian8(DHCP_OPTION_REQUESTED_IP_ADDRESS_LENGTH);
	*(uint32_t*)((requested_ip->data)) = endian32(dhcp_session->your_ip);

	DHCPOption* host_name = (DHCPOption*)((requested_ip->data) + requested_ip->length);
	host_name->code = endian8(DHCP_OPTION_HOST_NAME); 
	host_name->length = endian8(DHCP_OPTION_HOST_NAME_LENGTH); 
	*(uint32_t*)((host_name->data)) = endian32(HOST_NAME);

	DHCPOption* parameter_request = (DHCPOption*)((host_name->data) + host_name->length);
	parameter_request->code = endian8(DHCP_OPTION_PARAMETER_REQUEST_LIST); 
	parameter_request->length= endian8(DHCP_OPTION_PARAMETER_REQUEST_LIST_LENGTH);
	*(parameter_request->data) = DHCP_OPTION_SUBNETMASK;
	*((parameter_request->data) + 1) = DHCP_OPTION_ROUTERADDRESS;
	*((parameter_request->data) + 2) = DHCP_OPTION_DOMAIN_NAME;

	DHCPOption* end = (DHCPOption*)((parameter_request->data) + parameter_request->length);
	end->code = endian8(DHCP_OPTION_END);

	udp_pack(packet, sizeof(DHCP) + 40);
	if(!nic_output(packet->nic, packet)) {
		errno = DHCP_ERROR_REQUEST_FAIL;
		return false;
	}

	return true;
} 


static bool dhcp_discover(DHCPSession* dhcp_session) {
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

	Packet* packet = nic_alloc(nic, sizeof(Ether) + sizeof(IP) + sizeof(UDP) + sizeof(DHCP) + 42);
	if(!packet) {
		errno = DHCP_ERROR_NO_PACKET;
		return false;
	}

	memset(packet->buffer + packet->start, 0, sizeof(Ether) + sizeof(IP) + sizeof(UDP) + sizeof(DHCP) + 42);
	
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	ether->dmac = endian48(0xffffffffffff); 
	ether->smac = endian48(nic->mac);
	ether->type = endian16(ETHER_TYPE_IPv4);
		
	IP* ip = (IP*)ether->payload;
	ip->ihl = endian8(5); 
	ip->version = endian8(4);
	ip->ecn = endian8(0); 
	ip->dscp = endian8(0);
	ip->id = endian16(0);
	ip->flags_offset = 0x00;
	ip->ttl = endian8(IP_TTL);
	ip->protocol = endian8(IP_PROTOCOL_UDP);
	ip->source = endian32(0x00000000);
	ip->destination = endian32(0xffffffff);

	UDP* udp = (UDP*)ip->body;
	udp->source = endian16(DHCP_CLIENT_PORT);
	udp->destination = endian16(DHCP_SERVER_PORT);
	
	DHCP* dhcp = (DHCP*)udp->body;
	dhcp->op = endian8(0x0001);
	dhcp->htype = endian8(0x0001);
	dhcp->hlen = endian8(6);
	dhcp->hops = endian8(0x0000);
	dhcp->xid = endian32(transaction_id);
	dhcp->flags = endian8(0x0);
	dhcp->ciaddr = endian32(0x00000000);
	dhcp->yiaddr = endian32(0x00000000);
	dhcp->siaddr = endian32(0x00000000);
	dhcp->giaddr = endian32(0x00000000);
	*(dhcp->chaddr) = endian48(nic->mac);

	dhcp->magic_cookie = endian32(DHCP_MAGICCOOKIE); 
	DHCPOption* message_type =  (DHCPOption*)dhcp->options;
	message_type->code = endian8(DHCP_OPTION_MESSAGE_TYPE);
	message_type->length = DHCP_OPTION_MESSAGE_TYPE_LENGTH;
	*(message_type->data) = DHCP_TYPE_DISCOVER;

	DHCPOption* client_identifier = (DHCPOption*)(((message_type->data) + message_type->length));
	client_identifier->code = endian8(DHCP_OPTION_CLIENT_IDENTIFIER);
	client_identifier->length = DHCP_OPTION_CLIENT_IDENTIFIER_LENGTH;
	*(client_identifier->data) = DHCP_TYPE_DISCOVER;
	*(uint16_t*)((client_identifier->data) + 1) = endian16((nic->mac)>>32);
	*(uint32_t*)((client_identifier->data) + 3) = endian32(*(uint32_t*)(&(nic->mac)));

	DHCPOption* host_name = (DHCPOption*)(((client_identifier->data) + client_identifier->length));
	host_name->code = endian8(DHCP_OPTION_HOST_NAME); 
	host_name->length = endian8(DHCP_OPTION_HOST_NAME_LENGTH); 
	*(uint32_t*)((host_name->data)) = endian32(HOST_NAME);

	DHCPOption* parameter_request = (DHCPOption*)(((host_name->data) + host_name->length));
	parameter_request->code = endian8(DHCP_OPTION_PARAMETER_REQUEST_LIST); 
	parameter_request->length= endian8(DHCP_OPTION_PARAMETER_REQUEST_LIST_LENGTH);
	*(parameter_request->data) = DHCP_OPTION_SUBNETMASK;
	*((parameter_request->data) + 1) = DHCP_OPTION_ROUTERADDRESS;
	*((parameter_request->data) + 2) = DHCP_OPTION_DOMAIN_NAME;

	DHCPOption* end = (DHCPOption*)((parameter_request->data) + parameter_request->length);
	end->code = endian8(DHCP_OPTION_END);

	udp_pack(packet, sizeof(DHCP) + 42);
	if(!nic_output(packet->nic, packet)) {
		errno = DHCP_ERROR_DISCOVER_FAIL;	
	}

	return true;
}


static bool dhcp_distroy_session(NIC* nic, uint32_t t_id) {
	Map* state_map = nic_config_get(nic, DHCP_SESSION);
	if(!state_map) {
		errno = DHCP_ERROR_NO_MAP;
		return false;
	}

	DHCPSession* dhcp_state = map_get(state_map, (void*)(uintptr_t)t_id);
	if(!dhcp_state) {
		errno = DHCP_ERROR_NO_STATE;
		return false;
	}

	if(!map_remove(state_map, (void*)(uintptr_t)t_id)) {
		errno = DHCP_ERROR_MAP_REMOVE_FAIL;
		return false;
	}

	return true;

}



void dhcp_renewing_state(DHCPState *state) {
	/* Initialize state function */
	dhcp_state_init(state);

	/* Update state */
	state->current_state = RENEWING;
	/* Action */

	/* Next transaction states */
	if(state->received_packet_state == DHCP_TYPE_ACK) {
		state->received_packet_state = 0;
		state->next_state = dhcp_bound_state;
	} else if(state->received_packet_state == DHCP_TYPE_NAK){
		state->received_packet_state = 0;
		state->next_state = dhcp_init_state;
	}
}

void dhcp_bound_state(DHCPState *state) {
	/* Initialize state function */
	dhcp_state_init(state);

	/* Update state */
	state->current_state = BOUND;

	/* Action */
	DHCPSession* session = state->session;

	/* Next transaction states */
	if(state->received_packet_state == DHCP_TYPE_ACK) {
		state->received_packet_state = 0;
		if(session->request_timer_id && event_timer_remove(session->request_timer_id)) 
				session->request_timer_id = 0;
		if(session->acked)
			session->acked(session->nic, session->transaction_id, session->your_ip, session->context); 

		state->next_state = dhcp_renewing_state;
	} else if(state->received_packet_state == DHCP_TYPE_NAK){
		state->received_packet_state = 0;
		state->next_state = dhcp_init_state;
	}

}



void dhcp_requesting_state(DHCPState *state) {
	bool dhcp_resend_callback(void* context) {
		DHCPSession* session = context;
		dhcp_request(session);
		return false;
	}

	/* Initialize state function */
	dhcp_state_init(state);

	/* Update state */
	state->current_state = REQUESTING;

	/* Action */
	DHCPSession* session = state->session;
	uint32_t lease_time = state->lease_timer;
	
	/* Next transaction states */
	if(state->received_packet_state == DHCP_TYPE_NAK) {
		state->received_packet_state = 0;
		state->next_state = dhcp_init_state;
	} else if(state->received_packet_state == DHCP_TYPE_ACK) {
		state->received_packet_state = 0;
		uint64_t timer_id = event_timer_add(dhcp_resend_callback, session, lease_time*1000000, lease_time*1000000);
		session->request_timer_id = timer_id;
		state->next_state = dhcp_bound_state;
		//nic_ip_add(session->nic, session->your_ip);
	} else {
		state->received_packet_state = 0;
		return;
	}

//	state->requesting = dhcp_requesting_state;
}



void dhcp_selecting_state(DHCPState *state) {
	/* Initialize state function */
	dhcp_state_init(state);

	/* Update state */
	state->current_state = SELECTING;

	/* Action */
	if(state->received_packet_state != DHCP_TYPE_OFFER) {
		return;
	}

	DHCPSession* session = state->session;
	if(session->discover_timer_id && event_timer_remove(session->discover_timer_id)) {
		session->discover_timer_id = 0;
	}
	if(session->offered) {
		session->offered(session->nic, session->transaction_id, session->your_ip, session->context); 
	}
	bool check = dhcp_request(session);

	/* Next transaction states */
	if(check) {
		state->next_state = dhcp_requesting_state;
	} else {
		state->next_state = dhcp_init_state;
	}

	state->received_packet_state = 0;
}


void dhcp_init_state(DHCPState *state) {
	bool dhcp_timercallback(void* context) {
		DHCPSession* session = context;
		static int discover_count = 0;

		if(discover_count < 5) {
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
		
	/* Initialize state function */
	dhcp_state_init(state);

	/* Update state */
	state->current_state = INIT;
	printf("STATE INIT \n");

	/* Action */
	DHCPSession* session = state->session;
	bool check = dhcp_discover(session);
	uint64_t timer_id = event_timer_add(dhcp_timercallback, session, 5000000, 5000000);
	session->discover_timer_id = timer_id;

	/* Next transaction states */
	if(check) {
		state->next_state = dhcp_selecting_state;
	} else {
		state->received_packet_state = 0;
		return;
	}
	state->received_packet_state = 0;
}

uint32_t dhcp_lease_ip(NIC* nic, DHCPCallback offered, DHCPCallback acked, void* context) {
	if(!nic) {
		errno = DHCP_ERROR_NO_NIC;
		return 0;
	}

	Map* state_map = nic_config_get(nic, DHCP_SESSION);
	if(!state_map) {
		errno = DHCP_ERROR_NO_MAP;
		return 0;
	}

	DHCPState* dhcp_state = (DHCPState*)gmalloc(sizeof(DHCPState));
	if(!dhcp_state) {
		errno = DHCP_ERROR_MALLOC_FAIL;
		return 0;
	}

	DHCPSession* dhcp_session = (DHCPSession*)gmalloc(sizeof(DHCPSession));
	if(!dhcp_session) {
		errno = DHCP_ERROR_MALLOC_FAIL;
		return 0;
	}

	uint64_t _id = 0;
	uint32_t* id = (uint32_t*)&_id; 

	asm volatile("rdtsc" : "=a"(id[0]), "=d"(id[1]));

	uint32_t transaction_id = (_id % MAX) + 3;
	while(map_get(state_map, (void*)(uintptr_t)transaction_id)) {
		asm volatile("rdtsc" : "=a"(id[0]), "=d"(id[1]));
		transaction_id = (_id % MAX) + 3;
	}
	map_put(state_map, (void*)(uintptr_t)transaction_id, dhcp_state);

	dhcp_session->offered = offered;
	dhcp_session->acked = acked;
	dhcp_session->context = context;
	dhcp_session->transaction_id = transaction_id;
	dhcp_session->nic = nic;

	memset(dhcp_state, 0, sizeof(dhcp_state));
	dhcp_state->session = dhcp_session;
	dhcp_init_state(dhcp_state);

	return transaction_id;
}

bool dhcp_init(NIC* nic) {
	if(!nic) {
		errno = DHCP_ERROR_NO_NIC;
		return false;
	}

	Map* state_map = map_create(8, map_uint64_hash, map_uint64_equals, NULL);
	if(!state_map) {
		errno = DHCP_ERROR_NO_MAP;
		return false;
	}

	if(!nic_config_put(nic, DHCP_SESSION, (void*)(uintptr_t)state_map)) { 
		map_destroy(state_map);	
		errno = DHCP_ERROR_NIC_CONFIG_FAIL;
		return false;
	}

	return true;
}


static uint32_t dhcp_option_parser(DHCPOption* dop) {
	uint8_t code = dop->code;	
	uint8_t length = dop->length;	
	while(dop->code != DHCP_OPTION_END) {		
		if(code == DHCP_OPTION_LEASE_TIME) {
			return  endian32(*(uint32_t*)(dop->data));			
		}
		dop = (DHCPOption*)(((dop->data) + length));
		code = dop->code;
		length = dop->length;
	}
	return 0;
}

bool dhcp_process(Packet* _packet) {
	Packet* packet = _packet;
	if(!packet) {
		errno = DHCP_ERROR_NO_PACKET;
		return false;
	}

	Map* state_map = nic_config_get(packet->nic, DHCP_SESSION);
	if(!state_map) {
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

	DHCPState* dhcp_state = map_get(state_map, (void*)(uintptr_t)t_id);
	if(!dhcp_state) {
		errno = DHCP_ERROR_NO_STATE;
		return false;
	}

	DHCPSession* dhcp_session = dhcp_state->session;
	if(!dhcp_session) {
		errno = DHCP_ERROR_NO_SESSION;
		return false;
	}
	if(dhcp_session->transaction_id != t_id) {
		errno = DHCP_ERROR_TID;
		return false;
	}

	static uint32_t lease_time = 0;
	switch(*(dop->data)) {
		case DHCP_TYPE_NAK:
			dhcp_session->nic = NULL;
			dhcp_session->your_ip = 0; 		
			dhcp_session->gateway_ip = 0; 		
			dhcp_session->server_ip = 0; 		
			dhcp_session->discover_timer_id = 0;
			dhcp_session->request_timer_id = 0;
			dhcp_session->discovered = NULL;
			dhcp_session->offered = NULL;
			dhcp_session->acked = NULL;
		 	break;
		default:
			dhcp_session->your_ip = endian32(dhcp->yiaddr);
			dhcp_session->gateway_ip = endian32(dhcp->giaddr);
			dhcp_session->server_ip = endian32(dhcp->siaddr);
			lease_time = dhcp_option_parser(dop);
			if(lease_time != 0) 
				dhcp_session->lease_time = lease_time;	
			dhcp_state->received_packet_state = *(dop->data);

			DHCPState* d_state = dhcp_state;
			dhcp_state->next_state(d_state);
			return false;
	}

	return true;
}
