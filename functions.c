/*
 * functions.c
 *
 *  Created on: 15 oct. 2016
 *      Author: yorick
 */
#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>


#include <stdlib.h>
#include <arpa/inet.h>

#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "../inc/functions.h"

/**
 * Function used for debug purpose
 */
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header,  struct ether_header *eth_header, struct ip *ip)
{
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) // If IPv4
    {
    	printf("IP: %s - Packet capture length: %d - %ld\n", inet_ntoa(ip->ip_src), packet_header.caplen, packet_header.ts.tv_sec);
    }
}

signed int does_this_packet_exists_for_time_slot(const u_char *packet, unsigned long int packetCounterForTimeSlot, PacketList* packetTable, struct ip *ip)
{
	unsigned long int i = 0;

	char currentIP_string[100];
	strcpy(currentIP_string, inet_ntoa(ip->ip_src));

	for (i = 0; i < packetCounterForTimeSlot; i++)
	{
		if(strcmp(currentIP_string, packetTable[i].IPaddressChar) == 0) // Return 0 if the strings match
		{
			return i; // The IP has already been recorded in this time slot, return this number
		}
	}
	return DOES_NOT_EXIST; // The IP does not exist in the table
}

void sort_packet_table(unsigned long int packetCounter, PacketList* packetTable)
{
    unsigned long int stockSum = 0;
    char stockIPaddress[100];

    unsigned long int i, j;

	for(i = 0; i < packetCounter; i++)
	{
		for(j = i+1; j < packetCounter; j++)
		{
			if(packetTable[i].sumPacketSize < packetTable[j].sumPacketSize)
			{
				stockSum = packetTable[j].sumPacketSize;
				packetTable[j].sumPacketSize = packetTable[i].sumPacketSize;
				packetTable[i].sumPacketSize = stockSum;

				strcpy(stockIPaddress, packetTable[j].IPaddressChar);
				strcpy(packetTable[j].IPaddressChar, packetTable[i].IPaddressChar);
				strcpy(packetTable[i].IPaddressChar, stockIPaddress);
			}
		}
	}
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet)
{
	static unsigned long int packetCounter = 0;
	packetCounter++; //packetCounter is incremented every time a new packet is involved

	struct ip *ip = (struct ip*)(packet+sizeof(struct ether_header)); // IPv4

    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    int i = 0;

    static PacketList packetsInTimeSlot[100000];
    static unsigned long int packetCounterForTimeSlot = 0;
    static int isInitialized = FALSE;
    static unsigned long int timeReference = 0;

    // Initialize time slot
    if(isInitialized == FALSE)
    {
    	// Initialize IP table
		for(i = 0; i < 1000; i++)
		{
			packetsInTimeSlot[i].sumPacketSize = 0;
		}
		// Set the time reference
		timeReference = header->ts.tv_sec;

		// Print the first 10 sec time slot
		printf("_____________________\nTIME SLOT: %ld\n", timeReference);

		isInitialized = TRUE;
    }

	if((unsigned long int)header->ts.tv_sec >= (timeReference+10))
	{
		// End of the time slot: Sorting values
		sort_packet_table(packetCounterForTimeSlot, packetsInTimeSlot);

		// Give status for the time slot
		printf("-----------------------------------------------------------------\n");
		for(i = 0; i < packetCounterForTimeSlot; i++)
		{
			printf("Packet size: %lu - IP: %s\n", packetsInTimeSlot[i].sumPacketSize, packetsInTimeSlot[i].IPaddressChar);
		}
		printf("-----------------------------------------------------------------\n");

		packetCounterForTimeSlot = 0;

		// Switch to next time slot
		timeReference += 10;
		printf("\n_____________________\nTIME SLOT: %ld\n", timeReference);
	}

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) // If IPv4
    {
//    	print_packet_info(packet, *header, eth_header, ip); // Used for debug purpose

    	if(does_this_packet_exists_for_time_slot(packet, packetCounterForTimeSlot, packetsInTimeSlot, ip) == DOES_NOT_EXIST)
    	{
    		// Create this packet in our table
//    		printf("Create new packet\n"); // For debug purpose
    		strcpy(packetsInTimeSlot[packetCounterForTimeSlot].IPaddressChar, inet_ntoa(ip->ip_src));
    		packetsInTimeSlot[packetCounterForTimeSlot].sumPacketSize = header->len;
			packetCounterForTimeSlot++;
    	}

    	else
    	{
//    		printf("Packet aready exists\n"); // For debug purpose
    		// Increase the packet length for this IP
    		packetsInTimeSlot[does_this_packet_exists_for_time_slot(packet, packetCounterForTimeSlot, packetsInTimeSlot, ip)].sumPacketSize += header->len;
    	}
    }
    if(packetCounter == *((unsigned long int*)args)) // Last packet = Last time slot, should give a status
    {
    	sort_packet_table(packetCounterForTimeSlot, packetsInTimeSlot); // Sorting the results by packet length per IP

		// Give status for the time slot
		printf("-----------------------------------------------------------------\n");
		for(i = 0; i < packetCounterForTimeSlot; i++)
		{
			printf("packet size: %lu - IP: %s\n", packetsInTimeSlot[i].sumPacketSize, packetsInTimeSlot[i].IPaddressChar);
		}
		printf("-----------------------------------------------------------------\n");
    }
}
