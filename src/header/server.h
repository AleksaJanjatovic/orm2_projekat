#ifndef SERVER_H
#define SERVER_H
#include <pcap.h>
#include "utilities.h"

void packet_handler(pcap_t * device);
#endif // SERVER_H
