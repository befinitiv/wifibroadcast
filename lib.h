#include <stdint.h>
#include <stdlib.h>

typedef struct {
	int valid;
	size_t len; //this is the actual length of the packet stored in data
	uint8_t *data;
} packet_buffer_t;


packet_buffer_t *lib_alloc_packet_buffer_list(size_t num_packets, size_t packet_length);
