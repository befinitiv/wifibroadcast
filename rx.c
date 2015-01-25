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


#include "wifibroadcast.h"
#include "radiotap.h"


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
	u8 u8aSendBuffer[4096];
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int n80211HeaderLength = 0, nLinkEncap = 0;
	int retval, bytes;
	pcap_t *ppcap = NULL;
	struct bpf_program bpfprogram;
	char * szProgram = "", fBrokenSocket = 0;
	u16 u16HeaderLen;
	uint32_t last_seq_nr = -1;


	while (1) {
		int nOptionIndex;
		static const struct option optiona[] = {
			{ "help", no_argument, &flagHelp, 1 },
			{ 0, 0, 0, 0 }
		};
		int c = getopt_long(argc, argv, "h",
			optiona, &nOptionIndex);

		if (c == -1)
			break;
		switch (c) {
		case 0: // long option
			break;

		case 'h': // help
			usage();

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
			szProgram = "radio[0x4a:4]==0x13223344";
			break;

		case DLT_IEEE802_11_RADIO:
			fprintf(stderr, "DLT_IEEE802_11_RADIO Encap\n");
			n80211HeaderLength = 0x18; // ieee80211 comes after this
			szProgram = "ether[0x0a:4]==0x13223344";
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


	memset(u8aSendBuffer, 0, sizeof (u8aSendBuffer));

	while (!fBrokenSocket) {
		struct pcap_pkthdr * ppcapPacketHeader = NULL;
		struct ieee80211_radiotap_iterator rti;
		PENUMBRA_RADIOTAP_DATA prd;
		u8 * pu8Payload = u8aSendBuffer;
		int n;
		uint32_t seq_nr;
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

		//if we receive a new sequence number, we dump the content of the packet
		if(seq_nr != last_seq_nr) {
			write(STDOUT_FILENO, pu8Payload, bytes);

			//whops, we lost some packets
			if(seq_nr - last_seq_nr > 1){
				static int start_of_last_sequence_break = -1;
				static int cum_sent = 0, cum_lost = 0;	

				//if we have already received packets
				if(last_seq_nr != -1) {
					int sent_packet_count, lost_packet_count;
					float current_lpr;

					sent_packet_count = seq_nr - start_of_last_sequence_break;
					lost_packet_count = seq_nr - last_seq_nr - 1;
					current_lpr = 1.0 * lost_packet_count / sent_packet_count;

					cum_sent += sent_packet_count;
					cum_lost += lost_packet_count;

					fprintf(stderr, "Sent: %d\tLost: %d\tcurr LPR: %f\tavg LPR: %f\n", sent_packet_count, lost_packet_count, current_lpr, 1.0 * cum_lost / cum_sent);
				}

				start_of_last_sequence_break = seq_nr;

			}
			
			last_seq_nr = seq_nr;
		}
	}



	return (0);
}
