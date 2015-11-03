#include <stdint.h>
#include <stdlib.h>


typedef struct {
	uint32_t received_packet_cnt;
	uint32_t received_block_cnt;
	uint32_t damaged_block_cnt;
	uint32_t wrong_crc_cnt;
	uint32_t tx_restart_cnt;
	int8_t current_signal_dbm;
} wifibroadcast_rx_status_t;

typedef struct {
	int valid;
	int crc_correct;
	size_t len; //this is the actual length of the packet stored in data
	uint8_t *data;
} packet_buffer_t;


//this sits at the payload of the wifi packet (outside of FEC)
typedef struct {
    uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t;

//this sits at the data payload (which is usually right after the wifi_packet_header_t) (inside of FEC)
typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t;


packet_buffer_t *lib_alloc_packet_buffer_list(size_t num_packets, size_t packet_length);
