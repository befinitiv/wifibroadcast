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

#include <time.h>

#include "lib.h"
#include "wifibroadcast.h"

#define MAX_PACKET_LENGTH 4192
#define MAX_USER_PACKET_LENGTH 1470

/* this is the template radiotap header we send packets out with */

static const u8 u8aRadiotapHeader[] = {

	0x00, 0x00, // <-- radiotap version
	0x0c, 0x00, // <- radiotap header lengt
	0x04, 0x80, 0x00, 0x00, // <-- bitmap
	0x22, 
	0x0, 
	0x18, 0x00 
};

/* Penumbra IEEE80211 header */

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



int flagHelp = 0;



void
usage(void)
{
	printf(
	    "(c)2015 befinitiv. Based on packetspammer by Andy Green.  Licensed under GPL2\n"
	    "\n"
	    "Usage: tx [options] <interface>\n\nOptions\n"
	    "-r <count> Number of retransmissions (default 2)\n\n"
	    "-f <bytes> Maximum number of bytes per frame (default %d. max %d)\n"
			"-p <port> Port number 0-255 (default 0)\n"
			"-b <blocksize> Number of packets in a retransmission block (default 1). Needs to match with rx.\n"
	    "Example:\n"
	    "  echo -n mon0 > /sys/class/ieee80211/phy0/add_iface\n"
	    "  iwconfig mon0 mode monitor\n"
	    "  ifconfig mon0 up\n"
	    "  tx mon0        Reads data over stdion and sends it out over mon0\n"
	    "\n", MAX_USER_PACKET_LENGTH, MAX_USER_PACKET_LENGTH);
	exit(1);
}


int
main(int argc, char *argv[])
{
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int r, i;
	pcap_t *ppcap = NULL;
	char fBrokenSocket = 0;
	char szHostname[PATH_MAX];
	int pcnt = 0;
	time_t start_time;
	packet_buffer_t *packet_buffer_list;
	size_t packet_header_length = 0;
	int param_num_retr = 2;
	int param_packet_length = MAX_USER_PACKET_LENGTH;
	int param_port = 0;
	int param_retransmission_block_size = 1;


	if (gethostname(szHostname, sizeof (szHostname) - 1)) {
		perror("unable to get hostname");
	}
	szHostname[sizeof (szHostname) - 1] = '\0';


	printf("Raw data transmitter (c) 2015 befinitiv  GPL2\n");

	while (1) {
		int nOptionIndex;
		static const struct option optiona[] = {
			{ "help", no_argument, &flagHelp, 1 },
			{ 0, 0, 0, 0 }
		};
		int c = getopt_long(argc, argv, "r:hf:p:b:",
			optiona, &nOptionIndex);

		if (c == -1)
			break;
		switch (c) {
		case 0: // long option
			break;

		case 'h': // help
			usage();

		case 'r': // retransmissions
			param_num_retr = atoi(optarg);
			break;

		case 'f': // MTU
			param_packet_length = atoi(optarg);
			break;

		case 'p': //port
			param_port = atoi(optarg);
			break;

		case 'b': //retransmission block size
			param_retransmission_block_size = atoi(optarg);
			break;

		default:
			printf("unknown switch %c\n", c);
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();

	
	if(param_packet_length > MAX_USER_PACKET_LENGTH) {
		printf("Packet length is limited to %d bytes (you requested %d bytes)\n", MAX_USER_PACKET_LENGTH, param_packet_length);
		return (1);
	}

		// open the interface in pcap

	szErrbuf[0] = '\0';
	ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf);
	if (ppcap == NULL) {
		printf("Unable to open interface %s in pcap: %s\n",
		    argv[optind], szErrbuf);
		return (1);
	}


	pcap_setnonblock(ppcap, 1, szErrbuf);


	//dirty hack: the last byte of the mac address is the port number. this makes it easy to filter out specific ports via wireshark
	u8aIeeeHeader[SRC_MAC_LASTBYTE] = param_port;
	u8aIeeeHeader[DST_MAC_LASTBYTE] = param_port;


	packet_buffer_list = lib_alloc_packet_buffer_list(param_retransmission_block_size, MAX_PACKET_LENGTH);
	//prepare the buffers with headers
	for(i=0; i<param_retransmission_block_size; ++i) {
		u8 *pu8 = packet_buffer_list[i].data;
		memcpy(pu8, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
		pu8 += sizeof(u8aRadiotapHeader);
		memcpy(pu8, u8aIeeeHeader, sizeof (u8aIeeeHeader));
		pu8 += sizeof (u8aIeeeHeader);
				
		//determine the length of the header
		packet_header_length = pu8 - packet_buffer_list[i].data;
	}


 start_time = time(NULL);
 while (!fBrokenSocket) {
		int ret;

		//wait until we captured a whole retransmission block
		for(i=0; i<param_retransmission_block_size; ++i) {
			ssize_t inl;
			u8 *pu8 = packet_buffer_list[i].data + packet_header_length;
			*(uint32_t*)pu8 = pcnt;
			pu8 += 4;

			inl = read(STDIN_FILENO, pu8, param_packet_length);
			if(inl < 0 || inl > param_packet_length){
				perror("reading stdin");
				return 1;
			}

			packet_buffer_list[i].len = packet_header_length + inl + 4;

			pcnt++;
		}

		//send out the retransmission block several times
		for(ret=0; ret < param_num_retr; ++ret) {
			for(i=0; i< param_retransmission_block_size; ++i) {
				r = pcap_inject(ppcap, packet_buffer_list[i].data, packet_buffer_list[i].len);
				if (r != packet_buffer_list[i].len) {
					pcap_perror(ppcap, "Trouble injecting packet");
					return (1);
				}

			}
		}

		if(pcnt % 64 == 0) {
			printf("%d data packets sent (interface rate: %.3f)\n", pcnt, 1.0 * pcnt * param_num_retr / (time(NULL) - start_time));
		}

	}


	printf("Broken socket\n");

	return (0);
}
