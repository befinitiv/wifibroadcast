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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <time.h>

#include "lib.h"
#include "wifibroadcast.h"

#define MAX_PACKET_LENGTH 4192
#define MAX_USER_PACKET_LENGTH 1470
#define FIFO_NAME "/tmp/fifo%d"
#define MAX_FIFOS 8


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
			"-m <bytes> Minimum number of bytes per frame (default: 0)\n"
			"-s <stream> If <stream> is > 1 then the parameter changes \"tx\" input from stdin to named fifos. Each fifo transports a stream over a different port (starting at -p port and incrementing). Fifo names are \"%s\".\n"
	    "Example:\n"
	    "  echo -n mon0 > /sys/class/ieee80211/phy0/add_iface\n"
	    "  iwconfig mon0 mode monitor\n"
	    "  ifconfig mon0 up\n"
	    "  tx mon0        Reads data over stdion and sends it out over mon0\n"
	    "\n", MAX_USER_PACKET_LENGTH, MAX_USER_PACKET_LENGTH, FIFO_NAME);
	exit(1);
}

void set_port_no(uint8_t *pu, uint8_t port) {
	//dirty hack: the last byte of the mac address is the port number. this makes it easy to filter out specific ports via wireshark
	pu[sizeof(u8aRadiotapHeader) + SRC_MAC_LASTBYTE] = port;
	pu[sizeof(u8aRadiotapHeader) + DST_MAC_LASTBYTE] = port;
}


typedef struct {
	int seq_nr;
	int fd;
	int curr_pb;
	packet_buffer_t *pbl;
} fifo_t;


int fifo_init(fifo_t *fifo, int fifo_count, int retransmission_block_size) {
	int packet_header_length;
	int i;

	for(i=0; i<fifo_count; ++i) {
		int j;

		fifo[i].seq_nr = 0;
		fifo[i].fd = -1;
		fifo[i].curr_pb = 0;
		fifo[i].pbl = lib_alloc_packet_buffer_list(retransmission_block_size, MAX_PACKET_LENGTH);

		//prepare the buffers with headers
		for(j=0; j<retransmission_block_size; ++j) {
			u8 *pu8 = fifo[i].pbl[j].data;
			memcpy(pu8, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
			pu8 += sizeof(u8aRadiotapHeader);
			memcpy(pu8, u8aIeeeHeader, sizeof (u8aIeeeHeader));
			pu8 += sizeof (u8aIeeeHeader);
					
			//determine the length of the header
			packet_header_length = pu8 - fifo[i].pbl[j].data;
			fifo[i].pbl[j].len = packet_header_length;
		}
	}

	return packet_header_length;
}

void fifo_open(fifo_t *fifo, int fifo_count) {
	int i;
	if(fifo_count > 1) {
		//new FIFO style
		
		//first, create all required fifos
		for(i=0; i<fifo_count; ++i) {
			char fn[256];
			sprintf(fn, FIFO_NAME, i);
			
			unlink(fn);
			if(mkfifo(fn, 0666) != 0) {
				printf("Error creating FIFO \"%s\"\n", fn);
				exit(1);
			}
		}
		
		//second: wait for the data sources to connect
		for(i=0; i<fifo_count; ++i) {
			char fn[256];
			sprintf(fn, FIFO_NAME, i);
			
			printf("Waiting for \"%s\" being opened from the data source... \n", fn);			
			if((fifo[i].fd = open(fn, O_RDONLY)) < 0) {
				printf("Error opening FIFO \"%s\"\n", fn);
				exit(1);
			}
			printf("OK\n");
		}
	}
	else {
		//old style STDIN input
		fifo[0].fd = STDIN_FILENO;
	}
}


void fifo_create_select_set(fifo_t *fifo, int fifo_count, fd_set *fifo_set, int *max_fifo_fd) {
	int i;

	FD_ZERO(fifo_set);
	
	for(i=0; i<fifo_count; ++i) {
		FD_SET(fifo[i].fd, fifo_set);

		if(fifo[i].fd > *max_fifo_fd) {
			*max_fifo_fd = fifo[i].fd;
		}
	}
}


void pb_transmit_block(packet_buffer_t *pbl, pcap_t *ppcap, int port, int packet_header_len, int retransmission_block_size, int num_retr) {
	int ret, i, r;
	//send out the retransmission block several times
	for(ret=0; ret < num_retr; ++ret) {
		for(i=0; i< retransmission_block_size; ++i) {
			
			set_port_no(pbl[i].data, port);

			r = pcap_inject(ppcap, pbl[i].data, pbl[i].len);
			if (r != pbl[i].len) {
				pcap_perror(ppcap, "Trouble injecting packet");
				exit(1);
			}
		}
	}

	//reset the length back to the static headers
	for(i=0; i< retransmission_block_size; ++i) {
		pbl[i].len = packet_header_len;
	}

}


int
main(int argc, char *argv[])
{
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int i;
	pcap_t *ppcap = NULL;
	char fBrokenSocket = 0;
	int pcnt = 0;
	time_t start_time;
	size_t packet_header_length = 0;
	fd_set fifo_set;
	int max_fifo_fd = -1;
	fifo_t fifo[MAX_FIFOS];

	int param_num_retr = 2;
	int param_max_packet_length = MAX_USER_PACKET_LENGTH;
	int param_port = 0;
	int param_retransmission_block_size = 1;
	int param_min_packet_length = 0;
	int param_fifo_count = 1;



	printf("Raw data transmitter (c) 2015 befinitiv  GPL2\n");

	while (1) {
		int nOptionIndex;
		static const struct option optiona[] = {
			{ "help", no_argument, &flagHelp, 1 },
			{ 0, 0, 0, 0 }
		};
		int c = getopt_long(argc, argv, "r:hf:p:b:m:s:",
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
			param_max_packet_length = atoi(optarg);
			break;

		case 'p': //port
			param_port = atoi(optarg);
			break;

		case 'b': //retransmission block size
			param_retransmission_block_size = atoi(optarg);
			break;

		case 'm'://minimum packet length
			param_min_packet_length = atoi(optarg);
			break;

		case 's': //how many streams (fifos) do we have in parallel
			param_fifo_count = atoi(optarg);
			break;

		default:
			printf("unknown switch %c\n", c);
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();

	
	if(param_max_packet_length > MAX_USER_PACKET_LENGTH) {
		printf("Packet length is limited to %d bytes (you requested %d bytes)\n", MAX_USER_PACKET_LENGTH, param_max_packet_length);
		return (1);
	}

	if(param_min_packet_length > param_max_packet_length) {
		printf("Your minimum packet length is higher that your maximum packet length (%d > %d)\n", param_min_packet_length, param_max_packet_length);
		return (1);
	}

	if(param_fifo_count > MAX_FIFOS) {
		printf("The maximum number of streams (FIFOS) is %d (you requested %d)\n", MAX_FIFOS, param_fifo_count);
		return (1);
	}


	packet_header_length = fifo_init(fifo, param_fifo_count, param_retransmission_block_size);
	fifo_open(fifo, param_fifo_count);
	fifo_create_select_set(fifo, param_fifo_count, &fifo_set, &max_fifo_fd);

	
	
	// open the interface in pcap
	szErrbuf[0] = '\0';
	ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf);
	if (ppcap == NULL) {
		printf("Unable to open interface %s in pcap: %s\n",
		    argv[optind], szErrbuf);
		return (1);
	}


	pcap_setnonblock(ppcap, 1, szErrbuf);




 start_time = time(NULL);
 while (!fBrokenSocket) {
 		fd_set rdfs;
		int ret;


		rdfs = fifo_set;

		//wait for new data on the fifos
		ret = select(max_fifo_fd + 1, &rdfs, NULL, NULL, NULL);

		if(ret < 0) {
			perror("select");
			return (1);
		}

		//cycle through all fifos and look for new data
		for(i=0; i<param_fifo_count && ret; ++i) {
			if(!FD_ISSET(fifo[i].fd, &rdfs)) {
				continue;
			}

			ret--;

			packet_buffer_t *pb = fifo[i].pbl + fifo[i].curr_pb;
			
			//if the buffer is fresh we add the sequence-number
			if(pb->len == packet_header_length) {
				u8 *pu8 = pb->data + pb->len;
				*(uint32_t*)pu8 = fifo[i].seq_nr++;
				pb->len += 4;
			}

			//read the data
			int inl = read(fifo[i].fd, pb->data + pb->len, param_max_packet_length - pb->len);
			if(inl < 0 || inl > param_max_packet_length-pb->len){
				perror("reading stdin");
				return 1;
			}

			if(inl == 0) {
				//EOF
				printf("Warning: Lost connection to fifo %d. Please make sure that a data source is connected\n", i);
				usleep(1e5);
				continue;
			}

			pb->len += inl;
			
			//check if this packet is finished
			if(pb->len >= param_min_packet_length) {
				pcnt++;

				//check if this block is finished
				if(fifo[i].curr_pb == param_retransmission_block_size-1) {
					pb_transmit_block(fifo[i].pbl, ppcap, i+param_port, packet_header_length, param_retransmission_block_size, param_num_retr);
					fifo[i].curr_pb = 0;
				}
				else {
					fifo[i].curr_pb++;
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
