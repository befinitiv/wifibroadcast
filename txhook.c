// (c)2015 befinitiv

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


/* This library is a hook that overwrites the fwrite function and transmits
everything received via wifibroadcast.

Usage example:

LD_PRELOAD=./txhook.so raspivid .... -o -

*/


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <time.h>


#include "lib.h"
#include "wifibroadcast.h"

#define INTERFACE_NAME "wlan11"
#define MAX_PACKET_LENGTH 4192
#define MAX_USER_PACKET_LENGTH 512
#define RETRANSMISSION_COUNT 2


int init_done = 0;
uint8_t packet_transmit_buffer[MAX_PACKET_LENGTH];
char szErrbuf[PCAP_ERRBUF_SIZE];
pcap_t *ppcap = NULL;
char fBrokenSocket = 0;
int pcnt = 0;
size_t packet_header_length = 0;
time_t start_time;




static const u8 u8aRadiotapHeader[] = {

	0x00, 0x00, // <-- radiotap version
	0x0c, 0x00, // <- radiotap header lengt
	0x04, 0x80, 0x00, 0x00, // <-- bitmap
	0x22, 
	0x0, 
	0x18, 0x00 
};


//the last byte of the mac address is recycled as a port number
#define SRC_MAC_LASTBYTE 15
#define DST_MAC_LASTBYTE 21

static u8 u8aIeeeHeader[] = {
	0x08, 0x01, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x10, 0x86,
};

void set_port_no(uint8_t *pu, uint8_t port) {
	//dirty hack: the last byte of the mac address is the port number. this makes it easy to filter out specific ports via wireshark
	pu[sizeof(u8aRadiotapHeader) + SRC_MAC_LASTBYTE] = port;
	pu[sizeof(u8aRadiotapHeader) + DST_MAC_LASTBYTE] = port;
}


int packet_header_init(uint8_t *packet_header) {
			u8 *pu8 = packet_header;
			memcpy(packet_header, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
			pu8 += sizeof(u8aRadiotapHeader);
			memcpy(pu8, u8aIeeeHeader, sizeof (u8aIeeeHeader));
			pu8 += sizeof (u8aIeeeHeader);
					
			//determine the length of the header
			return pu8 - packet_header;
}


void pb_transmit_packet(pcap_t *ppcap, int seq_nr, uint8_t *packet_transmit_buffer, int packet_header_len, const uint8_t *packet_data, int packet_length, int last) {
		printf("SEQ: %d\tLAST: %d\n", seq_nr, last);

		size_t offset = packet_header_len;

    //add header
    wifi_packet_header_t *wph = (wifi_packet_header_t*)(packet_transmit_buffer + offset);
    wph->sequence_number = seq_nr;

		offset += sizeof(wifi_packet_header_t);

    //copy data
    memcpy(packet_transmit_buffer + offset, packet_data, packet_length);
		offset += packet_length;

		if(last) {
			*(uint32_t*)(packet_transmit_buffer + offset) = 0x01000000;
			offset += 4;
		}

    int r = pcap_inject(ppcap, packet_transmit_buffer, offset);
    if (r != offset) {
        pcap_perror(ppcap, "Trouble injecting packet");
        exit(1);
    }
}


void init_tx(void) {
	init_done = 1;


	printf("Initializing wifibroadcast txhook\n");
  packet_header_length = packet_header_init(packet_transmit_buffer);
	set_port_no(packet_transmit_buffer, 0);


	// open the interface in pcap
	szErrbuf[0] = '\0';
	ppcap = pcap_open_live(INTERFACE_NAME, 800, 1, 20, szErrbuf);
	if (ppcap == NULL) {
		printf("Unable to open interface %s in pcap: %s\n",
		    INTERFACE_NAME, szErrbuf);
		exit(1);
	}

	pcap_setnonblock(ppcap, 1, szErrbuf);

 start_time = time(NULL);


}
	


/*
		if(pcnt % 64 == 0) {
			printf("%d data packets sent (interface rate: %.3f)\n", pcnt, 1.0 * pcnt / param_data_packets_per_block * (param_data_packets_per_block + param_fec_packets_per_block) / (time(NULL) - start_time));
		}

*/


void process_nalu(const void *ptr, size_t len) {
	int rep = 2;//len > 200 ? RETRANSMISSION_COUNT : 1; //only transmit meaningful packages several times
	int i;
	int tseqnr;

	for(i=0; i<rep; ++i){
		size_t tlen = len;
		const void *tptr = ptr;
		tseqnr = pcnt;

		while(tlen > 0){
			int last = 0;
			int plen;

			printf("tlen %d\n", tlen);

			if(tlen > MAX_USER_PACKET_LENGTH){
				plen = MAX_USER_PACKET_LENGTH;
			}
			else {
				plen = tlen;
				//last = 1;
			}

			pb_transmit_packet(ppcap, tseqnr, packet_transmit_buffer, packet_header_length, tptr, plen, last);

			tlen -= plen;
			tptr += plen;
			tseqnr++;
		}
	}

	pcnt = tseqnr;



}

		


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
		if(!init_done)
			init_tx();

		process_nalu(ptr, nmemb);

		printf("Written %d bytes\n", (int)nmemb);
    return nmemb;
}

