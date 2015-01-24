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

static const u8 u8aIeeeHeader[] = {
	0x08, 0x01, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x10, 0x86,
};

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
	    "Usage: tx [options] <interface>\n\nOptions\n"
	    "-r <count> Number of retransmissions\n\n"
	    "-f <bytes> Maximum number of bytes per frame\n"
	    "Example:\n"
	    "  echo -n mon0 > /sys/class/ieee80211/phy0/add_iface\n"
	    "  iwconfig mon0 mode monitor\n"
	    "  ifconfig mon0 up\n"
	    "  tx mon0        Reads data over stdion and sends it out over mon0\n"
	    "\n");
	exit(1);
}


int
main(int argc, char *argv[])
{
	u8 u8aSendBuffer[4096];
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int r, nRep = 3;
	pcap_t *ppcap = NULL;
	char fBrokenSocket = 0;
	char szHostname[PATH_MAX];
	int pcnt = 0;
	int packet_length = 512;

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
		int c = getopt_long(argc, argv, "r:hf:",
			optiona, &nOptionIndex);

		if (c == -1)
			break;
		switch (c) {
		case 0: // long option
			break;

		case 'h': // help
			usage();

		case 'r': // retransmissions
			nRep = atoi(optarg);
			break;

		case 'f': // MTU
			packet_length = atoi(optarg);
			break;

		default:
			printf("unknown switch %c\n", c);
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();


		// open the interface in pcap

	szErrbuf[0] = '\0';
	ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf);
	if (ppcap == NULL) {
		printf("Unable to open interface %s in pcap: %s\n",
		    argv[optind], szErrbuf);
		return (1);
	}


	pcap_setnonblock(ppcap, 1, szErrbuf);


	memset(u8aSendBuffer, 0, sizeof (u8aSendBuffer));

 while (!fBrokenSocket) {
		u8 * pu8 = u8aSendBuffer;
		int rep;

		u8 inp_data[2048];
		ssize_t inl;


		memcpy(u8aSendBuffer, u8aRadiotapHeader,
			sizeof (u8aRadiotapHeader)
		);
		pu8 += sizeof (u8aRadiotapHeader);



		memcpy(pu8, u8aIeeeHeader, sizeof (u8aIeeeHeader));
		pu8 += sizeof (u8aIeeeHeader);


		*(uint32_t*)pu8 = pcnt;
		pu8 += 4;

		inl = read(STDIN_FILENO, inp_data, packet_length);
		if(inl < 0 || inl > sizeof(inp_data)){
			perror("reading stdin");
			return 1;
		}

		memcpy(pu8, inp_data, inl);
		pu8 += inl;

		for(rep=0; rep < nRep; ++rep) {
		r = pcap_inject(ppcap, u8aSendBuffer, pu8 - u8aSendBuffer);
		if (r != (pu8-u8aSendBuffer)) {
			printf("Trouble injecting packet");
			return (1);
		}
		}

		if(pcnt % 64 == 0)
			printf("%d\n", pcnt);
		
		pcnt++;
	}


	printf("Broken socket\n");

	return (0);
}
