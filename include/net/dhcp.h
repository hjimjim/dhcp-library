#ifndef __NET_DHCP_H__
#define __NET_DHCP_H__

#include <net/nic.h>
#include <util/list.h>
#include <errno.h>
								// code length
#define DHCP_OPTION_SUBNETMASK				0x01	// 1 	4
#define DHCP_OPTION_SUBNETMASK_LENGTH			0x04	
#define DHCP_OPTION_ROUTERADDRESS			0x03	// 3 	4
#define DHCP_OPTION_ROUTERADDRESS_LENGTH		0x04	
#define DHCP_OPTION_DOMAINNAMESERVER			0x06	// 6 	8
#define DHCP_OPTION_DOMAINNAMESERVER_LENGTH		0x08	
#define DHCP_OPTION_HOST_NAME				0x0c	// 12	14
#define DHCP_OPTION_HOST_NAME_LENGTH			0x0e	
#define DHCP_OPTION_DOMAIN_NAME				0x0f	// 15	9
#define DHCP_OPTION_DOMAIN_NAME_LENGTH			0x09	
#define DHCP_OPTION_REQUESTED_IP_ADDRESS		0x32 	// 50	4
#define DHCP_OPTION_REQUESTED_IP_ADDRESS_LENGTH		0x04 	
#define DHCP_OPTION_LEASE_TIME				0x33 	// 51	4
#define DHCP_OPTION_LEASE_TIME_LENGTH			0x04 	
#define DHCP_OPTION_MESSAGE_TYPE			0x35	// 53	1
#define DHCP_OPTION_MESSAGE_TYPE_LENGTH			0x01	
#define DHCP_OPTION_SEVER_IDENTIFIER			0x36	// 54	4
#define DHCP_OPTION_SEVER_IDENTIFIER_LENGTH		0x04	
#define DHCP_OPTION_PARAMETER_REQUEST_LIST		0x37	// 55	11
#define DHCP_OPTION_PARAMETER_REQUEST_LIST_LENGTH	0x0b	
#define DHCP_OPTION_RENEWAL_TIME_VALUE			0x3a	// 58	4
#define DHCP_OPTION_RENEWAL_TIME_VALUE_LENGTH		0x04	
#define DHCP_OPTION_REBINDING_TIME_VALUE		0x3b	// 59	4
#define DHCP_OPTION_REBINDING_TIME_VALUE_LENGTH		0x04	
#define DHCP_OPTION_VENDOR_CLASS_IDENTIFIER		0x3c	// 60	8
#define DHCP_OPTION_VENDOR_CLASS_IDENTIFIER_LENGTH	0x08	
#define DHCP_OPTION_CLIENT_IDENTIFIER			0x3d	// 61	7
#define DHCP_OPTION_CLIENT_IDENTIFIER_LENGTH		0x07	
#define DHCP_OPTION_END					0xff	// 255

#define DHCP_CLIENT_PORT				68
#define DHCP_SERVER_PORT				67

#define DHCP_MAGICCOOKIE				0x63825363  // 99.130.83.99

#define DHCP_ERROR_INIT_FAIL				1
#define DHCP_ERROR_DISCOVER_FAIL			2
#define DHCP_ERROR_REQUEST_FAIL				3
#define DHCP_ERROR_NO_NIC				4
#define DHCP_ERROR_NO_MAP				5
#define DHCP_ERROR_NO_PACKET				6
#define DHCP_ERROR_NO_SESSION				7
#define DHCP_ERROR_NO_STATE				8 
#define DHCP_ERROR_NIC_CONFIG_FAIL			9 	
#define DHCP_ERROR_MAP_REMOVE_FAIL			10 
#define DHCP_ERROR_MALLOC_FAIL				11
#define DHCP_ERROR_TID					12
#define DHCP_ERROR_OPTION				13

#define DHCP_TYPE_INIT					0
#define DHCP_TYPE_DISCOVER				1
#define DHCP_TYPE_OFFER					2
#define DHCP_TYPE_REQUEST				3
#define DHCP_TYPE_DECLINE				4
#define DHCP_TYPE_ACK					5
#define DHCP_TYPE_NAK					6
#define DHCP_TYPE_RELEASE				7
#define DHCP_TYPE_INFORM				8

typedef struct _DHCPSession DHCPSession;
typedef void (*dhcp_state_func[2])(DHCPSession *st);

typedef enum _DHCP_STATE_TAG { INIT, SELECTING, REQUESTING, BOUND, REBINDING, RENEWING }DHCP_STATE_TAG;

/**
 * DHCP payload
 */
typedef struct _DHCP {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;

	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;

	uint64_t chaddr[2];	// 128
	char sname[64];	// 64
	char fname[128];		// 128	zero padding

	uint32_t magic_cookie;
	uint8_t options[0];
} __attribute__ ((packed)) DHCP;

typedef struct _DHCPOption {
	uint8_t code;
	uint8_t length;
	uint8_t data[0];
} __attribute__ ((packed)) DHCPOption; 

// DHCPCallback
typedef bool(*DHCPCallback)(NIC* nic, uint32_t transaction_id, uint32_t ip, void* context);

typedef struct _DHCPSession {
	NIC* nic;
	uint32_t transaction_id;
	uint32_t your_ip;	// Your IP
	uint32_t gateway_ip;	// GW IP
	uint32_t server_ip;	// GW IP
	uint64_t discover_timer_id;	
	uint64_t request_timer_id;	
	uint32_t lease_time;	
	DHCPCallback discovered;
	DHCPCallback offered;
	DHCPCallback acked;

	DHCP_STATE_TAG current_state;
	dhcp_state_func next_state;

	void* context;
} DHCPSession;

//typedef struct _DHCPState {
//	DHCP_STATE_TAG current_state;
//	dhcp_state_func next_state;
//	DHCPSession* session;
//	uint8_t message_type;
//} DHCPState;

/**
 * Make session table for each nic
 * @param nic NIC
 * @return true if session table is configured safely  
 */
bool dhcp_init(NIC* nic);

/**
 * Process dhcp packet
 * @param packet Packet
 */
bool dhcp_process(Packet* packet);

/**
 * Create DHCP Session
 * @param nic NIC
 * @param discovered CallFunc
 * @param offered CallFunc
 * @param ack_received CallFunc
 * @return return true if leasing ip is successfully done 
 */
bool dhcp_lease_ip(NIC* nic, DHCPCallback offered, DHCPCallback acked, void* context);

List* dhcp_ip_get_all(NIC* nic);
#endif /* __NET_DHCP_H__ */
