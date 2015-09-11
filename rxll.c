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


#include "fec.h"


#include "lib.h"
#include "wifibroadcast.h"
#include "radiotap.h"

#define MAX_PACKET_LENGTH 4192
#define MAX_USER_PACKET_LENGTH 1450
#define MAX_DATA_OR_FEC_PACKETS_PER_BLOCK 32

#define DEBUG 0
#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)





// this is where we store a summary of the
// information from the radiotap header

typedef struct  {
	int m_nChannel;
	int m_nChannelFlags;
	int m_nRate;
	int m_nAntenna;
	int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;



int flagHelp = 0;
int param_port = 0;
int param_window_length = 50;

int win_bot = 0;
int win_top = 0;

void
usage(void)
{
/*
	printf(
	    "(c)2015 befinitiv. Based on packetspammer by Andy Green.  Licensed under GPL2\n"
	    "\n"
	    "Usage: rx [options] <interfaces>\n\nOptions\n"
			"-p <port> Port number 0-255 (default 0)\n"
			"-b <count> Number of data packets in a block (default 8). Needs to match with tx.\n"
	    "-r <count> Number of FEC packets per block (default 4). Needs to match with tx.\n\n"
	    "-f <bytes> Number of bytes per packet (default %d. max %d). This is also the FEC block size. Needs to match with tx\n"
			"-d <blocks> Number of transmissions blocks that are buffered (default 1). This is needed in case of diversity if one adapter delivers data faster than the other. Note that this increases latency\n"
	    "Example:\n"
	    "  iwconfig wlan0 down\n"
	    "  iw dev wlan0 set monitor otherbss fcsfail\n"
	    "  ifconfig wlan0 up\n"
			"  iwconfig wlan0 channel 13\n"
	    "  rx wlan0        Receive raw packets on wlan0 and output the payload to stdout\n"
	    "\n", MAX_USER_PACKET_LENGTH, MAX_USER_PACKET_LENGTH);
			*/
		printf("todo...\n");
	exit(1);
}

typedef struct {
	pcap_t *ppcap;
	int selectable_fd;
	int n80211HeaderLength;
} monitor_interface_t;


void open_and_configure_interface(const char *name, int port, monitor_interface_t *interface) {
	struct bpf_program bpfprogram;
	char szProgram[512];
	char szErrbuf[PCAP_ERRBUF_SIZE];
		// open the interface in pcap

	szErrbuf[0] = '\0';
	interface->ppcap = pcap_open_live(name, 2048, 1, -1, szErrbuf);
	if (interface->ppcap == NULL) {
		fprintf(stderr, "Unable to open interface %s in pcap: %s\n",
		    name, szErrbuf);
		exit(1);
	}
	

	if(pcap_setnonblock(interface->ppcap, 1, szErrbuf) < 0) {
		fprintf(stderr, "Error setting %s to nonblocking mode: %s\n", name, szErrbuf);
	}

	int nLinkEncap = pcap_datalink(interface->ppcap);

	switch (nLinkEncap) {

		case DLT_PRISM_HEADER:
			fprintf(stderr, "DLT_PRISM_HEADER Encap\n");
			interface->n80211HeaderLength = 0x20; // ieee80211 comes after this
			sprintf(szProgram, "radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x", port);
			break;

		case DLT_IEEE802_11_RADIO:
			fprintf(stderr, "DLT_IEEE802_11_RADIO Encap\n");
			interface->n80211HeaderLength = 0x18; // ieee80211 comes after this
			sprintf(szProgram, "ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x", port);
			break;

		default:
			fprintf(stderr, "!!! unknown encapsulation on %s !\n", name);
			exit(1);

	}

	if (pcap_compile(interface->ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
		puts(szProgram);
		puts(pcap_geterr(interface->ppcap));
		exit(1);
	} else {
		if (pcap_setfilter(interface->ppcap, &bpfprogram) == -1) {
			fprintf(stderr, "%s\n", szProgram);
			fprintf(stderr, "%s\n", pcap_geterr(interface->ppcap));
		} else {
		}
		pcap_freecode(&bpfprogram);
	}

	interface->selectable_fd = pcap_get_selectable_fd(interface->ppcap);
}



void process_payload(uint8_t *data, size_t data_len, int crc_correct, packet_buffer_t *packet_buffer_list, int adapter_no)
{
    wifi_packet_header_t *wph;
    int i;

    wph = (wifi_packet_header_t*)data;
    data += sizeof(wifi_packet_header_t);
    data_len -= sizeof(wifi_packet_header_t);



		fprintf(stderr, "Received seqnr %d (winbot %d\twintop %d)\n", wph->sequence_number, win_bot, win_top);

    int tx_restart = wph->sequence_number+128 < win_bot;
    if(tx_restart && crc_correct) {
			fprintf(stderr, "TX RESTART: Detected sequence number far before the current window\n");

			win_bot = win_top = wph->sequence_number;

			for(i=0; i<param_window_length; ++i) {
					packet_buffer_list[i].valid = 0;
			}
		}

		if(wph->sequence_number > win_top)
			win_top = wph->sequence_number;

		if(crc_correct) {
			//as long as the span between bottom and the top is larger that the window size, evacuate the lower fields
			while(win_top-win_bot >= param_window_length) {
				uint32_t win_bot_idx = win_bot % param_window_length;
				packet_buffer_t *p = packet_buffer_list + win_bot_idx;
				
				if(p->valid) {
					fprintf(stderr, "WTL: Evacuating %d (idx %d)\n", win_bot, win_bot_idx);

					write(STDOUT_FILENO, p->data, p->len);
					p->valid = 0;
					p->crc_correct = 0;
					p->len = 0;
				}
				win_bot++;
			}
		}
		
		
		
		//sequence number lies outside of the lower border of the window -> too late, ignore it (plus window length because in case of fault free transmission win_bot can be one window length ahead of the current sequence number
		if(wph->sequence_number < win_bot) {
			if(wph->sequence_number+param_window_length< win_bot) {
				fprintf(stderr, "Received package outside of window. seqnr %d win_bot %d (window too small?)\n", wph->sequence_number, win_bot);	
			}
			return;
		}

		
		uint32_t curr_idx = wph->sequence_number % param_window_length;
		packet_buffer_t *p = packet_buffer_list + curr_idx;

		//only overwrite the buffer if it has not already been filled correctly
		if(p->crc_correct == 0) {
				fprintf(stderr, "Saving %d to %d\n", wph->sequence_number, curr_idx);

			p->valid = 1;
			p->crc_correct = crc_correct;
			p->len = data_len;
			memcpy(p->data, data, data_len);
		}

		//check if we have finished pkgs at the bottom and evacuate them
		while(win_bot <= win_top) {
			uint32_t win_bot_idx = win_bot % param_window_length;
			packet_buffer_t *p = packet_buffer_list + win_bot_idx;

			if(p->crc_correct) {
				fprintf(stderr, "FIN: Evacuating %d (idx %d)\n", win_bot, win_bot_idx);
				
				write(STDOUT_FILENO, p->data, p->len);
				p->valid = 0;
				p->crc_correct = 0;
				p->len = 0;
			}
			else
			{
				break;
			}
			win_bot++;	
		}

}


void process_packet(monitor_interface_t *interface, packet_buffer_t *packet_buffer_list, int adapter_no) {
		struct pcap_pkthdr * ppcapPacketHeader = NULL;
		struct ieee80211_radiotap_iterator rti;
		PENUMBRA_RADIOTAP_DATA prd;
		u8 payloadBuffer[MAX_PACKET_LENGTH];
		u8 *pu8Payload = payloadBuffer;
		int bytes;
		int n;
		int retval;
		int u16HeaderLen;

		// receive


		retval = pcap_next_ex(interface->ppcap, &ppcapPacketHeader,
		    (const u_char**)&pu8Payload);

		if (retval < 0) {
			fprintf(stderr, "Socket broken\n");
			fprintf(stderr, "%s\n", pcap_geterr(interface->ppcap));
			exit(1);
		}

		//if(retval == 0)
		//	fprintf(stderr, "retval = 0\n");

		if (retval != 1)
			return;


		u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

		if (ppcapPacketHeader->len <
		    (u16HeaderLen + interface->n80211HeaderLength))
			return;

		bytes = ppcapPacketHeader->len -
			(u16HeaderLen + interface->n80211HeaderLength);
		if (bytes < 0)
			return;

		if (ieee80211_radiotap_iterator_init(&rti,
		    (struct ieee80211_radiotap_header *)pu8Payload,
		    ppcapPacketHeader->len) < 0)
			return;

		while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

			switch (rti.this_arg_index) {
			case IEEE80211_RADIOTAP_RATE:
				prd.m_nRate = (*rti.this_arg);
				break;

			case IEEE80211_RADIOTAP_CHANNEL:
				prd.m_nChannel =
				    le16_to_cpu(*((u16 *)rti.this_arg));
				prd.m_nChannelFlags =
				    le16_to_cpu(*((u16 *)(rti.this_arg + 2)));
				break;

			case IEEE80211_RADIOTAP_ANTENNA:
				prd.m_nAntenna = (*rti.this_arg) + 1;
				break;

			case IEEE80211_RADIOTAP_FLAGS:
				prd.m_nRadiotapFlags = *rti.this_arg;
				break;
			}
		}
		pu8Payload += u16HeaderLen + interface->n80211HeaderLength;

		if (prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS)
			bytes -= 4;


        int checksum_correct = (prd.m_nRadiotapFlags & 0x40) == 0;

        process_payload(pu8Payload, bytes, checksum_correct, packet_buffer_list, adapter_no);
}

int
main(int argc, char *argv[])
{
	monitor_interface_t interfaces[MAX_PENUMBRA_INTERFACES];
	int num_interfaces = 0;
	int i;


	while (1) {
		int nOptionIndex;
		static const struct option optiona[] = {
			{ "help", no_argument, &flagHelp, 1 },
			{ 0, 0, 0, 0 }
		};
		int c = getopt_long(argc, argv, "hw:p:",
			optiona, &nOptionIndex);

		if (c == -1)
			break;
		switch (c) {
		case 0: // long option
			break;

		case 'h': // help
			usage();

		case 'p': //port
			param_port = atoi(optarg);
			break;
		
		case 'w':
            param_window_length = atoi(optarg);
			break;

		default:
			fprintf(stderr, "unknown switch %c\n", c);
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();
	


	int x = optind;
	while(x < argc && num_interfaces < MAX_PENUMBRA_INTERFACES) {
		open_and_configure_interface(argv[x], param_port, interfaces + num_interfaces);
		++num_interfaces;
		++x;
	}



	packet_buffer_t *packet_buffer_list = lib_alloc_packet_buffer_list(param_window_length, MAX_PACKET_LENGTH);

	for(;;) { 
		fd_set readset;
		struct timeval to;

		to.tv_sec = 0;
		to.tv_usec = 1e5;
	
		FD_ZERO(&readset);
		for(i=0; i<num_interfaces; ++i)
			FD_SET(interfaces[i].selectable_fd, &readset);

		int n = select(30, &readset, NULL, NULL, &to);

		for(i=0; i<num_interfaces; ++i) {
			if(n == 0)
				break;
			if(FD_ISSET(interfaces[i].selectable_fd, &readset)) {
                process_packet(interfaces + i, packet_buffer_list, i);
			}
		}

	}

	return (0);
}
