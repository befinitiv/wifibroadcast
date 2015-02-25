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



#include "lib.h"
#include "wifibroadcast.h"
#include "radiotap.h"

#define MAX_PACKET_LENGTH 4192

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

void
usage(void)
{
	printf(
	    "(c)2015 befinitiv. Based on packetspammer by Andy Green.  Licensed under GPL2\n"
	    "\n"
	    "Usage: rx [options] <interface>\n\nOptions\n"
			"-p <port> Port number 0-255 (default 0)\n"
			"-b <blocksize> Number of packets in a retransmission block (default 1). Needs to match with tx.\n"
	    "Example:\n"
	    "  echo -n mon0 > /sys/class/ieee80211/phy0/add_iface\n"
	    "  iwconfig mon0 mode monitor\n"
	    "  ifconfig mon0 up\n"
	    "  rx mon0        Receive raw packets on mon0 and output the payload to stdout\n"
	    "\n");
	exit(1);
}


int
main(int argc, char *argv[])
{
	u8 u8aSendBuffer[MAX_PACKET_LENGTH];
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int n80211HeaderLength = 0, nLinkEncap = 0;
	int retval, bytes;
	pcap_t *ppcap = NULL;
	struct bpf_program bpfprogram;
	char szProgram[512], fBrokenSocket = 0;
	u16 u16HeaderLen;
	packet_buffer_t *packet_buffer_list;
	uint32_t last_block_num = -1;
	int num_received = 0, num_lost = 0;
	int i;
	int param_port = 0;
	int param_retransmission_block_size = 1;


	while (1) {
		int nOptionIndex;
		static const struct option optiona[] = {
			{ "help", no_argument, &flagHelp, 1 },
			{ 0, 0, 0, 0 }
		};
		int c = getopt_long(argc, argv, "hp:b:",
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
		
		case 'b': //retransmission block size
			param_retransmission_block_size = atoi(optarg);
			break;

		default:
			fprintf(stderr, "unknown switch %c\n", c);
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();


		// open the interface in pcap

	szErrbuf[0] = '\0';
	ppcap = pcap_open_live(argv[optind], 2048, 1, 20, szErrbuf);
	if (ppcap == NULL) {
		fprintf(stderr, "Unable to open interface %s in pcap: %s\n",
		    argv[optind], szErrbuf);
		return (1);
	}

	nLinkEncap = pcap_datalink(ppcap);

	switch (nLinkEncap) {

		case DLT_PRISM_HEADER:
			fprintf(stderr, "DLT_PRISM_HEADER Encap\n");
			n80211HeaderLength = 0x20; // ieee80211 comes after this
			sprintf(szProgram, "radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x", param_port);
			break;

		case DLT_IEEE802_11_RADIO:
			fprintf(stderr, "DLT_IEEE802_11_RADIO Encap\n");
			n80211HeaderLength = 0x18; // ieee80211 comes after this
			sprintf(szProgram, "ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x", param_port);
			break;

		default:
			fprintf(stderr, "!!! unknown encapsulation on %s !\n", argv[1]);
			return (1);

	}

	if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
		puts(szProgram);
		puts(pcap_geterr(ppcap));
		return (1);
	} else {
		if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
			fprintf(stderr, "%s\n", szProgram);
			fprintf(stderr, "%s\n", pcap_geterr(ppcap));
		} else {
		}
		pcap_freecode(&bpfprogram);
	}


	packet_buffer_list = lib_alloc_packet_buffer_list(param_retransmission_block_size, MAX_PACKET_LENGTH);

	while (!fBrokenSocket) {
		struct pcap_pkthdr * ppcapPacketHeader = NULL;
		struct ieee80211_radiotap_iterator rti;
		PENUMBRA_RADIOTAP_DATA prd;
		u8 * pu8Payload = u8aSendBuffer;
		int n;
		uint32_t seq_nr;
		int block_num;
		int packet_num;
		// receive

		retval = pcap_next_ex(ppcap, &ppcapPacketHeader,
		    (const u_char**)&pu8Payload);

		if (retval < 0) {
			fBrokenSocket = 1;
			continue;
		}

		if (retval != 1)
			continue;

		u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

		if (ppcapPacketHeader->len <
		    (u16HeaderLen + n80211HeaderLength))
			continue;

		bytes = ppcapPacketHeader->len -
			(u16HeaderLen + n80211HeaderLength);
		if (bytes < 0)
			continue;

		if (ieee80211_radiotap_iterator_init(&rti,
		    (struct ieee80211_radiotap_header *)pu8Payload,
		    ppcapPacketHeader->len) < 0)
			continue;

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
		pu8Payload += u16HeaderLen + n80211HeaderLength;

		if (prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS)
			bytes -= 4;

		//first 4 bytes are the sequence number
		seq_nr = *(uint32_t*)pu8Payload;
		pu8Payload += 4;
		bytes -= 4;

//printf("got seqno %d\n", seq_nr);

		block_num = seq_nr / param_retransmission_block_size;
//printf("got blocknono %d (last: %d)\n", block_num, last_block_num);

		//if we received the start of a new block, we need to write out the old one
		if(block_num != last_block_num) { //TODO: and FCS correct

			//write out block
			for(i=0; i<param_retransmission_block_size; ++i) {
				packet_buffer_t *p = packet_buffer_list + i;
				if(p->valid) {
					num_received++;
					write(STDOUT_FILENO, p->data, p->len);
				}
				else {
					fprintf(stderr, "Lost a packet! Lossrate: %f\t(%d / %d)\n", 1.0 * num_lost/num_received, num_lost, num_received);
					num_lost++;
				}

				p->valid = 0;
				p->len = 0;
			}		
			last_block_num = block_num;
		}
		
		packet_num = seq_nr % param_retransmission_block_size;
//printf("got packetnum %d\n", packet_num);

		//if the checksum is correct or it is still unitialized, then save the packet
		if(/*FCS correct || */packet_buffer_list[packet_num].valid == 0) {
			memcpy(packet_buffer_list[packet_num].data, pu8Payload, bytes);
			packet_buffer_list[packet_num].len = bytes;
			packet_buffer_list[packet_num].valid = 1;
		}

	}



	return (0);
}
