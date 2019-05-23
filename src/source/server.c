#include <stdio.h>
#include <stdlib.h>
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
    /* LINUX COMPATIBILITY END */

    pthread_mutex_t circular_buffer_lock;
#endif



int server_receive_packet(pcap_if_t * device, packet_circular_buffer_t * buffer) {
    unsigned char result = 0;
    struct pcap_pkthdr ** pkt_header; //Ovo se koristi za statistiku;

#ifdef _WIN32
    /* WINDOWS COMPATIBILITY BEGIN */


    /* WINDOWS COMPATIBILITY END */
#else
    /* LINUX COMPATIBILITY BEGIN */
    //Koristiti circular_buffer_lock za sinhronizaciju sa funkcijom server_send_packet

    /* LINUX COMPATIBILITY END */
#endif

}

int server_send_packet(pcap_if_t * device, packet_circular_buffer_t * buffer) {
    unsigned char result = 0;

#ifdef _WIN32
    /* WINDOWS COMPATIBILITY BEGIN */


    /* WINDOWS COMPATIBILITY END */
#else
    /* LINUX COMPATIBILITY BEGIN */
    //Koristiti

    /* LINUX COMPATIBILITY END */
#endif
}



int main(int argc, char *argv[]) {
    pcap_if_t * device_list;        //List of network interfaces
    pcap_if_t * ethernet_device; //Ethernet interface
    pcap_if_t * wifi_device;  //Wifi interface

    //Sa obzirom da server samo prenosi pakete od jednog korisnika do drugog
    //koristimo circular buffer koji se koristi izmedju niti za slanje i primanje
    //Sinhronizacija je zamisljena tako da nit koja salje pakete ceka dook se
    //buffer ne popuni
        //Ideje realizovanja niti
            //1. Dve niti: prva za primanje i slanje paketa za wifi koja odma
                //prosledjuje paket kada joj stigne, a druga isto to samo za Ethernet
            //2. Cetiri niti: dve za slanje i primanje za Wifi i za Ethernet
            //3. Dve niti: prva za primanje preko wifi-a i ethernet-a, druga
                //za slanje preko wifi-a i ethernet-a
    packet_circular_buffer_t * buffer;
    //

    char errorMsg[PCAP_ERRBUF_SIZE + 1];


    unsigned char i, j, k; //iterators
    unsigned char number_of_sending = atoi(argv[1]);

    // Retrieve the device list
    if(pcap_findalldevs(&device_list, errorMsg) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", errorMsg);
        return -1;
    }

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

    packet_circular_buffer_init(buffer);

#ifdef _WIN32

#else
    /* LINUX COMPATIBILITY BEGIN */
    pthread_t sending_thread[2]; //One sending thread is for WiFi, other is for internet
    pthread_t recieving_thread[2]; //One receiving thread is for WiFi, other is for internet
    /* LINUX COMPATIBILITY END */
#endif

    return 0;
}