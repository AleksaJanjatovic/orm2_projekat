#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <string.h>
#include "../header/server.h"
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
    //MUTEX MORA BITI OVDE, AKO SE JA DOBRO SECAM
    pthread_mutex_t packet_sequence_mutex;
    /* LINUX COMPATIBILITY END */
#endif

/* CONSTANT MACROS BEGIN */
#define PACKET_ARRAY_MAX_LEN 500
#define REDIRECT_CONFIRMATION 7
/* CONSTANT MACROS END */

/* GLOBAL VARIABLES BEGIN */
unsigned int number_of_packets_recieved = 0;
unsigned char redirect_thread_number = 0;
unsigned int redirect_sleep_time[2] = {MINIMUM_TIMEOUT_TIME, MINIMUM_TIMEOUT_TIME};
packet_t packet_sequence[PACKET_ARRAY_MAX_LEN]; //Ovo indeksiras sa sekvencom paketa
unsigned char packet_received_confirmation[PACKET_ARRAY_MAX_LEN];
const unsigned char home_MAC[6] = {0x08, 0x00, 0x27, 0x6a, 0x1e, 0x78};	// ZAPAMTI DA NAMESTIS NA SVOJ IP I MAC
const unsigned char dest_MAC[6] = {0x08, 0x00, 0x27, 0x6a, 0x1e, 0x78};
const unsigned char home_ip[4] = {192, 168, 1, 1};
const unsigned char dest_ip[4] = {192, 168, 1, 1};
const unsigned short home_port = 6000;
const unsigned short dest_port = 6000;
/* GLOBAL VARIABLES END */

int redirect_package(pcap_t * device) {
	
    struct pcap_pkthdr * pkt_header;
    unsigned char receive_sleep_time = MINIMUM_TIMEOUT_TIME;

    packet_t * received_packet; //Ovo treba zameniti tako da se koristi packet_receiving_array
    while((received_packet = (packet_t*)pcap_next(device, pkt_header)) == NULL) {
        if(receive_sleep_time < MAXIUM_TIMEOUT_TIME) {
#ifdef _WIN32
            Sleep((receive_sleep_time *= 2)/1000);
#else
            usleep(receive_sleep_time *= 2);
#endif
        }
        printf("Wait cycle skipped.\n");
    } //Radi ovo dok ne primis packet

    printf("Packet number %d recieved.\n", received_packet->packet_number);

    if((calc_ip_checksum(&received_packet->iph) == ntohs(received_packet->iph.checksum)) && (calc_udp_checksum(received_packet) == ntohs(received_packet->udph.checksum))) {
       printf("Checksum of packet %d correct\n", received_packet->packet_number);
#ifdef _WIN32

#else
       pthread_mutex_lock(&packet_sequence_mutex);
#endif
       received_packet->eth = create_eth_header(home_MAC, dest_MAC);
       received_packet->iph = create_ip_header(PACKET_DATA_LEN, home_ip, dest_ip);
       received_packet->udph = create_udp_header(home_port, dest_port, PACKET_DATA_LEN);
       received_packet->udph.checksum = calc_udp_checksum(received_packet);
       if(packet_received_confirmation[received_packet->packet_number] == 0) {
            packet_received_confirmation[received_packet->packet_number] = 1;
            packet_sequence[received_packet->packet_number] = *received_packet;

            if(number_of_packets_recieved >= received_packet->expected_packet_num) { //mora post increment da bi poslali i poslednji ack paket
                return REDIRECT_CONFIRMATION; //indikacija da smo zavrsili sa threadom
            } else {
                //while potencijalno
                if(pcap_sendpacket(device, (char*)&packet_sequence[received_packet->packet_number], sizeof(packet_t))) {
                    printf("Error while sending ACK packet %d\n", received_packet->packet_number);
                }
            }
       }
#ifdef _WIN32

#else
       pthread_mutex_unlock(&packet_sequence_mutex);
#endif

    }
    // unsigned short checksum = ntohs(p->udph->checksum); // ovu treba iskoristiti
	
    //long data_len = htons(p->udph->datagram_length) - sizeof(udp_header);
	
	// TODO
	
	// proveriti checksum -> ako valja
	// inkrementirati broj primljenih paketa
	// ubaciti paket u odgovarajuci array (recieved_packets[PACKET_ARRAY_MAX_LEN])?
	// upisati u odgovarajucu packet array sekvencu (packet_sequence[PACKET_ARRAY_MAX_LEN])?
	
	// kada upisujemo u fajl? kako uopste znamo da smo primili sve pakete?
	
	// napraviti novi ACK paket
	// poslati ga sa sendpacket
}

void* thread_function_redirect(void * device) {
    unsigned char this_thread_number = redirect_thread_number++;
    int result = 0;
    while(1) {
#ifdef _WIN32
        Sleep(redirect_sleep_time[this_thread_number]/1000);
#else
        usleep(redirect_sleep_time[this_thread_number]);
#endif
        if((result = redirect_package((pcap_t *)device)) == REDIRECT_CONFIRMATION) {
            printf("ALL PACKETS RECEIVED\n");
            return NULL;
        }
    }
}

int main(int argc, char *argv[]) {

    pcap_if_t * ethernet_device_item, * wifi_device_item; 	//Ethernet interface, Wifi interface
    pcap_if_t * devices;        							//List of network interfaces
    pcap_t * ethernet_device; 								//Ethernet interface
    pcap_t * wifi_device;  									//Wifi interface
    
    struct bpf_program fcode;
    char filter[] = "udp and dst port 6000";
    
    FILE * data_file;

    char errorMsg[PCAP_ERRBUF_SIZE + 1];
	
	unsigned int netmask;
    char filter_exp[] = "";

    unsigned char i, j, k; //iterators

    //initialize packet_sequence
    memset(packet_sequence, 0, sizeof(packet_t)*PACKET_ARRAY_MAX_LEN);
    memset(packet_received_confirmation, 0 , sizeof(char)*PACKET_ARRAY_MAX_LEN);

    // Retrieve the device list
    if(pcap_findalldevs(&devices, errorMsg) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", errorMsg);
        return -1;
    }

    //OVO MORA DA STOJI ZATO STO NAM TREBAJU DVA UREDJAJA ZA SLANJE
    //JEDAN ZA WIFI DRUGI ZA ETHERNET
    printf("Izaberite odgovarajuci ethernet interfejs\n");
    ethernet_device_item = select_device(devices);
    
    printf("Izaberite odgovarajuci WiFi interfejs\n");
    wifi_device_item = select_device(devices);

    // Open the ethernet device for sending
    if ((ethernet_device = pcap_open_live(ethernet_device_item->name,		// name of the device
    									65536,						// portion of the packet to capture (65536 guarantees that the whole 																		   packet will be captured on all the link layers)
                                        0,							// non promiscuous mode
                                        MINIMUM_TIMEOUT_TIME,		// read timeout
        								errorMsg					// buffer where error message is stored
    									)) == NULL)
    {
        printf("%s", errorMsg);
        printf("\nUnable to open the %s ethernet adapter.", ethernet_device_item->name);
        pcap_freealldevs(devices);
        return -1;
    }

	//Checking if ethernet device was chosen
    if(pcap_datalink(ethernet_device) != DLT_EN10MB) 	{
        printf("\nChoose a valid Ethernet based device.\n");
        pcap_freealldevs(devices);
        return -1;
    }
    
    // Set netmask
#ifdef _WIN32
	if(ethernet_device_item->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(ethernet_device_item->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff;
#else
    if (!ethernet_device_item->addresses->netmask)
        netmask = 0;
    else
        netmask = ((struct sockaddr_in *)(ethernet_device_item->addresses->netmask))->sin_addr.s_addr;
#endif

	// Compile the filter
	if (pcap_compile(ethernet_device, &fcode, filter, 1, netmask) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}

	// Set the filter
	if (pcap_setfilter(ethernet_device, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

    //Open the WiFi device for sending
    if ((wifi_device = pcap_open_live(wifi_device_item->name,		// name of the device
                                        65536,						// portion of the packet to capture (65536 guarantees that the whole 																		   packet will be captured on all the link layers)
                                        0,							// promiscuous mode
                                        MINIMUM_TIMEOUT_TIME,		// read timeout
                                        errorMsg					// buffer where error message is stored
                                        )) == NULL)
    {
        printf("%s", errorMsg);
        printf("\nUnable to open the %s WiFi adapter.", wifi_device_item->name);
        pcap_freealldevs(devices);
        return -1;
    }
    
    printf("A");
    
    /*//Checking if WiFi device was chosen
    if(pcap_datalink(wifi_device) != DLT_IEEE802_11) 	{
        printf("\nChoose a valid WiFi based device.\n");
        pcap_freealldevs(devices);
        return -1;
    }*/
    
    // Set netmask
#ifdef _WIN32
	if(wifi_device_item->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(wifi_device_item->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff;
#else
    if (!wifi_device_item->addresses->netmask)
        netmask = 0;
    else
        netmask = ((struct sockaddr_in *)(wifi_device_item->addresses->netmask))->sin_addr.s_addr;
#endif

	// Compile the filter
	if (pcap_compile(wifi_device, &fcode, filter, 1, netmask) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}

	// Set the filter
	if (pcap_setfilter(wifi_device, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}
#ifdef _WIN32

#else
    pthread_mutex_init(&packet_sequence_mutex, NULL);
    pthread_t redirect_thread[2];
    pthread_create(&redirect_thread[0], NULL, thread_function_redirect, (void*)wifi_device);
    pthread_create(&redirect_thread[1], NULL, thread_function_redirect, (void*)ethernet_device);
    pthread_detach(redirect_thread[0]);
    pthread_detach(redirect_thread[1]);
#endif
    while(1) {
        usleep(100000000);
    }
    return 0;
}
