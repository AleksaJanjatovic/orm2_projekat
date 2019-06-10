#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include "../header/client.h"
#include "../header/utilities.h"

#ifdef _MSC_VER
    /* WINDOWS COMPATIBILITY BEGIN */
    #define _CRT_SECURE_NO_WARNINGS
    #include <windows.h>
    /* WINDOWS COMPATIBILITY END */
#else
    /* LINUX COMPATIBILITY BEGIN */
    #include <netinet/in.h>
    #include <pthread.h>
    /* LINUX COMPATIBILITY END */
#endif

int client_receive_packets(pcap_if_t * device, packet_t * packet_receiving_array) {
    unsigned char result = 0;
    struct pcap_pkthdr ** pkt_header; //Ovo se koristi za statistiku;
    const u_char ** pcap_temp_data; //Ovo treba zameniti tako da se koristi packet_receiving_array
    while((result = pcap_next_ex(device, pkt_header, pcap_temp_data)) >= 0) {
        //Cuvanje paketa i njihova obrada
    }
}

int client_send_packets(pcap_if_t * device, packet_t * packet_sending_array) {
    unsigned char result = 0;

}

/* CONSTANT MACROS BEGIN */
#define PACKET_ARRAY_MAX_LEN 100
/* CONSTANT MACROS END */

int main(int argc, char *argv[]) {
/*HEAD
    pcap_if_t * device_list;        //List of network interfaces
    pcap_if_t * ethernet_device; //Ethernet interface
    pcap_if_t * wifi_device;  //Wifi interface
*/
    pcap_if_t * devices;        //List of network interfaces
    pcap_if_t * current_device; //Current network interface
	pcap_t* device_handle;

    packet_t recieving_packets[PACKET_ARRAY_MAX_LEN], sending_packets[PACKET_ARRAY_MAX_LEN]; //PACKET_ARRAY
    char errorMsg[PCAP_ERRBUF_SIZE + 1];
    
    unsigned int netmask;
    char filter_exp[] = "";

    unsigned char i, j, k; //iterators
    unsigned char number_of_sending = atoi(argv[1]);

    // Retrieve the device list
    if(pcap_findalldevs(&device_list, errorMsg) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", errorMsg);
        return -1;
    }

/* HEAD
    ethernet_device = select_device(device_list);
    wifi_device = select_device(device_list);

    //Checking if Ethernet device was choosen
    if(pcap_datalink(ethernet_device) != DLT_EN10MB) 	{
        printf("\nChoose a valid Ethernet based device.\n");
        return -1;
    }
    //Checking if WiFi device was choosen
    if(pcap_datalink(ethernet_device) != DLT_IEEE802_11) 	{
        printf("\nChoose a valid Ethernet based device.\n");
        return -1;
    }
*/

    current_device = select_device(devices);
    
    // Check if device is valid
	if (current_device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}
    
    // Open the capture device
    if ((device_handle = pcap_open_live(current_device->name,		// name of the device
    									65536,						// portion of the packet to capture (65536 guarantees that the whole 																		   packet will be captured on all the link layers)
    									1,							// promiscuous mode
    									2000,						// read timeout
        								errorMsg					// buffer where error message is stored
    									)) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", current_device->name);
        pcap_freealldevs(devices);
        return -1;
    }
    
    // Check the link layer. We support only Ethernet for simplicity.
    if (pcap_datalink(device_handle) != DLT_EN10MB)
    {
        printf("\nThis program works only on Ethernet networks.\n");
        return -1;
    }
    
    // TODO
    // Podesiti filtere i poslati paket
    
#ifdef _WIN32

#else
    /* LINUX COMPATIBILITY BEGIN */
    pthread_t sending_thread[2]; //One sending thread is for WiFi, other is for internet
    pthread_t recieving_thread[2]; //One receiving thread is for WiFi, other is for internet
    /* LINUX COMPATIBILITY END */
#endif

    return 0;
}
