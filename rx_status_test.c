#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "lib.h"

wifibroadcast_rx_status_t *status_memory_open(void) {
	int fd = shm_open("/wifibroadcast_rx_status", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

	if(fd < 0) {
		perror("shm_open");
		exit(1);
	}

	if (ftruncate(fd, sizeof(wifibroadcast_rx_status_t)) == -1) {
		perror("ftruncate");
		exit(1);
	}

	void *retval = mmap(NULL, sizeof(wifibroadcast_rx_status_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (retval == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	
	
	return (wifibroadcast_rx_status_t*)retval;

}


int main(void) {

	wifibroadcast_rx_status_t *t = status_memory_open();

	for(;;) {
		printf("\033[2J\r");
		printf("Signal:\t\t\t%ddBm\n\n", t->current_signal_dbm);
		printf("Received Pkg:\t\t%d\n", t->received_packet_cnt);
		printf("Received Block:\t\t%d\n", t->received_block_cnt);
		printf("Damaged Block:\t\t%d\n", t->damaged_block_cnt);
		printf("Wrong CRC:\t\t%d\n", t->wrong_crc_cnt);
		printf("TX restart:\t\t%dn", t->tx_restart_cnt);
		usleep(1e5);
	}

	return 0;
}
