#include <net/nic.h>
#ifndef __NET_DHCP_H__

#define __NET_DHCP_H__

							// code length
#define DHCP_OPTION_MESSAGE_TYPE  		0x35	// 53	1
#define DHCP_OPTION_CLIENT_IDENTIFIER		0x3d	// 61	7
#define DHCP_OPTION_REQUESTED_IP_ADDRESS	0x32 	// 50	4
#define DHCP_OPTION_HOST_NAME			0x0c	// 12	14
#define DHCP_OPTION_SUBNETMASK			0x01	// 1 	4
#define DHCP_OPTION_ROUTERADDRESS		0x03	// 3 	4
#define DHCP_OPTION_DOMAINNAMESERVER		0x06	// 6 	8
#define DHCP_OPTION_DOMAIN_NAME			0x0f	// 15	9
#define DHCP_OPTION_VENDOR_CLASS_IDENTIFIER	0x3c	// 60	8
#define DHCP_OPTION_PARAMETER_REQUEST_LIST	0x37	// 55	11
#define DHCP_OPTION_RENEWAL_TIME_VALUE		0x3a	// 58	4
#define DHCP_OPTION_REBINDING_TIME_VALUE	0x3b	// 59	4
#define DHCP_OPTION_END				0xff	// 255

#define DHCP_CLIENT_PORT	68
#define DHCP_SERVER_PORT	67

#define DHCP_TYPE_DISCOVER	1
#define DHCP_TYPE_OFFER		2
#define DHCP_TYPE_REQUEST	3
#define DHCP_TYPE_ACK		4

#define DHCP_MAGICCOOKIE	0x63825363  //99.130.83.99

/**
 * DHCP payload
 */
typedef struct _DHCP {
	uint8_t op_code;
	uint8_t hw_type;
	uint8_t hw_length;
	uint8_t hops;

	uint32_t transaction_id;
	uint16_t seconds;
	uint16_t flags;
	
	uint32_t client_ip;
	uint32_t your_ip;
	uint32_t server_ip;
	uint32_t gateway_ip;

	uint64_t client_hw_addr;	// 128
	uint64_t client_hw_addr_padding;// Zero
	uint64_t server_name[8];	// 64
	uint64_t file_name[16];		// 128	zero padding

	uint32_t magic_cookie;
	uint8_t options[0];
} __attribute__ ((packed)) DHCP;


typedef struct _DHCPOption {
	uint8_t code;
	uint8_t length;
	uint8_t data[0];
} __attribute__ ((packed)) DHCPOption; 

//typedef struct _DHCPCallback {
////	bool (*discovered)(NIC* nic, uint32_t transaction_id);
//	bool (*offered)(NIC* nic, uint32_t transaction_id);
//	bool (*ack_received)();
//} DHCPCallback;

typedef bool(*CallFunc)(NIC* nic, uint32_t transaction_id, uint32_t ip, void* context);

typedef struct _DHCPSession {
	NIC* nic;
	uint32_t transaction_id;
	uint32_t your_ip;	// Your IP
	uint32_t gateway_ip;	// GW IP
	uint32_t discover_timer_id;	
	CallFunc discovered;
	CallFunc offered;
	CallFunc ack_received;
	void* context;
} DHCPSession;


/**
 * Make session table for each nic
 * @param nic NIC
 * @return true if session table is configured safely  
 */
bool dhcp_init(NIC* ni);

/**
 * Process dhcp packet
 * @param packet Packet
 */
bool dhcp_process(Packet* packet);

/**
 * Send DHCP discover packet
 * @param nic NIC
 * @param dhcp_callback DHCPCallback
 * @return true if dhcp discover is sent
 */
bool dhcp_discover(NIC* ni, uint32_t transaction_id);

/**
 * Send DHCP request packet 
 * @param nic NIC
 * @return true if dhcp request is sent
 */
bool dhcp_request(NIC* ni, uint32_t transactionId);

/**
 * Create DHCP Session
 * @param nic NIC
 * @param discovered CallFunc
 * @param offered CallFunc
 * @param ack_received CallFunc
 * @return transactionId 
 */
uint32_t dhcp_create_session(NIC* ni, CallFunc discovered, CallFunc offered,
						 CallFunc ack_received, void* context);

bool distory_dhcp_session(NIC* ni, uint32_t transactionId);

/**
 *  
 * 
 */
bool dhcp_bound();

#endif /* __NET_DHCP_H__ */
