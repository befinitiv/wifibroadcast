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



/* This program can be used in conjunction with the txhook.so library.
Together they form a stdin wifibroadcast application.
Usage example:

LD_PRELOAD=./txhook.so ./txhookpipe < /dev/urandom

*/


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define MAXLEN 1024

int main(void) {
	uint8_t buf[1 << 14];
	ssize_t n;

	//open something so that the initializer is called
	FILE *dummy = fopen("/dev/zero", "r");
	(void) dummy;


	for(;;) {
		uint8_t *p = buf;
		n = read(STDIN_FILENO, p, sizeof(buf));

		if(n < 0) {
			perror("txhookpipe: Error reading from stdin");
			return 1;
		}
		if(n == 0) {
			return 0;
		}

		while(n > 0) {
			int len = MAXLEN;
			if(n < MAXLEN)
				len = n;
			fwrite(p, 1, len, stdout);
			printf("write %d\n",len);
			p+=len;
			n-=len;
		}
	}

	return 0;
}
	
