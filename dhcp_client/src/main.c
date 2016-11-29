#include <stdio.h>
#include <string.h>
#include <thread.h>
#include <readline.h>
#include <net/nic.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/dhcp.h>
#include <util/event.h>

bool private_ip_acked(NIC* nic, uint32_t transaction_id, uint32_t ip, void* _data) {
        printf("private ip leased. %p\n", ip);
        printf("private ip leased. %d\n", nic);
	
	if(!nic_ip_add(nic, ip))
		printf("ssssssssssssssssssss \n");
        return true;
}

void ginit(int argc, char** argv) {
	uint32_t i;
        uint32_t count = nic_count();
	for(i=0; count > i; i++) {
                NIC* nic = nic_get(i);
                dhcp_init(nic);
                printf("dhcp_init\n");
        }
}

void init(int argc, char** argv) {
}

void process(NIC* ni) {
	Packet* packet = nic_input(ni);
	if(!packet)
		return;
	if(dhcp_process(packet))
		return;
	if(arp_process(packet))
		return;
	if(icmp_process(packet))
		return;
	if(packet)
		nic_free(packet);
}

void destroy() {
}

void gdestroy() {
}

int main(int argc, char** argv) {
	printf("Thread %d booting\n", thread_id());
	if(thread_id() == 0) {
		ginit(argc, argv);
	}
	
	thread_barrior();
	
	init(argc, argv);
	
	thread_barrior();
	
	uint32_t i = 0;
	while(1) {
		uint32_t count = nic_count();
		if(count > 0) {
			i = (i + 1) % count;
			
			NIC* nic = nic_get(i);
			if(nic_has_input(nic)) {
				process(nic);
			}
			char* line = readline();
			if(line!=NULL && !strcmp(line,"lease")) {
				dhcp_lease_ip(nic, NULL, private_ip_acked, NULL);
			}
		}
	}

	thread_barrior();
	
	destroy();
	
	thread_barrior();
	
	if(thread_id() == 0) {
		gdestroy(argc, argv);
	}
	
	return 0;
}
